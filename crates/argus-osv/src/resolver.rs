use crate::cache::{
    coordinate_cache_key, lookup_cache, CacheEntry, CacheQuerySummary, SecureCache,
};
use crate::client::{CompleteSnapshot, OsvClient, OsvTransport};
use crate::model::{CoordinateQuery, CoordinateSet, NormalizedAdvisory, OsvError, OsvErrorKind};
use argus_core::VulnerabilitySourceMode;
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub struct ResolveRequest<'a> {
    pub coordinates: &'a CoordinateSet,
    pub offline: bool,
    pub allow_stale: bool,
    pub max_age_seconds: u64,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinateSource {
    Cache,
    Network,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCoordinate {
    pub query: CoordinateQuery,
    pub fetched_at: DateTime<Utc>,
    pub query_summaries: Vec<CacheQuerySummary>,
    pub advisories: Vec<NormalizedAdvisory>,
    pub source: CoordinateSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSnapshot {
    pub coordinates: CoordinateSet,
    pub results: Vec<ResolvedCoordinate>,
    pub source_mode: VulnerabilitySourceMode,
    pub authorized_stale: bool,
    pub resolved_at: DateTime<Utc>,
}

pub trait AdvisoryResolver {
    fn resolve(
        &self,
        request: ResolveRequest<'_>,
        transport: Option<&dyn OsvTransport>,
    ) -> Result<ResolvedSnapshot, OsvError>;
}

#[derive(Clone)]
pub struct OsvResolver {
    cache: SecureCache,
    cache_dir: PathBuf,
}

impl OsvResolver {
    pub fn new(cache: SecureCache, cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache,
            cache_dir: cache_dir.into(),
        }
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    fn network_entries(
        &self,
        refresh: Vec<CoordinateQuery>,
        transport: &dyn OsvTransport,
        now: DateTime<Utc>,
    ) -> Result<(CompleteSnapshot, Vec<CacheEntry>), OsvError> {
        let refresh_set = CoordinateSet::new(refresh, 0)?;
        let snapshot = OsvClient::new(transport).query(&refresh_set)?;
        if snapshot.queries.len() != refresh_set.queries.len() {
            return Err(internal("network snapshot lost a queried coordinate"));
        }
        let mut entries = Vec::with_capacity(snapshot.queries.len());
        for (expected, result) in refresh_set.queries.iter().zip(&snapshot.queries) {
            if expected != &result.query {
                return Err(internal(
                    "network snapshot query order does not match requested coordinates",
                ));
            }
            entries.push(CacheEntry {
                coordinate: result.query.coordinate.clone(),
                fetched_at: now,
                query_summaries: result
                    .summaries
                    .iter()
                    .map(|summary| CacheQuerySummary {
                        primary_id: summary.primary_id.clone(),
                        modified: summary.modified.clone(),
                    })
                    .collect(),
                advisories: result.advisories.clone(),
                response_sha256: String::new(),
            });
        }
        Ok((snapshot, entries))
    }
}

impl AdvisoryResolver for OsvResolver {
    fn resolve(
        &self,
        request: ResolveRequest<'_>,
        transport: Option<&dyn OsvTransport>,
    ) -> Result<ResolvedSnapshot, OsvError> {
        request.coordinates.validate()?;
        let envelope = self.cache.load_at(&self.cache_dir, request.now)?;
        let lookup = lookup_cache(
            envelope.as_ref(),
            request.coordinates,
            request.now,
            request.max_age_seconds,
            request.offline,
            request.allow_stale,
        )?;
        let had_cache_hits = !lookup.hits.is_empty();
        let authorized_stale = lookup.authorized_stale;
        let mut entries = lookup.hits;
        let refresh = lookup.refresh;
        let refreshed_keys = refresh
            .iter()
            .map(|query| coordinate_cache_key(&query.coordinate))
            .collect::<Result<BTreeSet<_>, _>>()?;

        if !refresh.is_empty() {
            let transport = transport.ok_or_else(|| {
                OsvError::new(
                    OsvErrorKind::Transport,
                    "online cache refresh requires the fixed OSV transport",
                )
            })?;
            let (_, incoming) = self.network_entries(refresh, transport, request.now)?;
            let committed = self.cache.commit(&self.cache_dir, incoming, request.now)?;
            for key in &refreshed_keys {
                let entry = committed
                    .entries
                    .get(key)
                    .cloned()
                    .ok_or_else(|| internal("committed cache lost a refreshed coordinate"))?;
                entries.insert(key.clone(), entry);
            }
        }

        let source_mode = if request.offline {
            if authorized_stale {
                VulnerabilitySourceMode::OfflineStale
            } else {
                VulnerabilitySourceMode::OfflineFresh
            }
        } else if refreshed_keys.is_empty() {
            VulnerabilitySourceMode::Cache
        } else if had_cache_hits {
            VulnerabilitySourceMode::Mixed
        } else {
            VulnerabilitySourceMode::Network
        };
        let mut results = Vec::with_capacity(request.coordinates.queries.len());
        for query in &request.coordinates.queries {
            let key = coordinate_cache_key(&query.coordinate)?;
            let entry = entries
                .remove(&key)
                .ok_or_else(|| internal("complete resolution lost a queried coordinate"))?;
            let mut advisories = entry.advisories;
            for advisory in &mut advisories {
                advisory.coordinate = query.coordinate.clone();
                advisory.evidence.locators = query.locators.clone();
            }
            advisories.sort_by(|left, right| left.primary_id.cmp(&right.primary_id));
            results.push(ResolvedCoordinate {
                query: query.clone(),
                fetched_at: entry.fetched_at,
                query_summaries: entry.query_summaries,
                advisories,
                source: if refreshed_keys.contains(&key) {
                    CoordinateSource::Network
                } else {
                    CoordinateSource::Cache
                },
            });
        }
        if !entries.is_empty() {
            return Err(internal(
                "cache lookup returned coordinates outside the requested set",
            ));
        }
        Ok(ResolvedSnapshot {
            coordinates: request.coordinates.clone(),
            results,
            source_mode,
            authorized_stale,
            resolved_at: request.now,
        })
    }
}

fn internal(detail: impl Into<String>) -> OsvError {
    OsvError::new(OsvErrorKind::Internal, detail)
}
