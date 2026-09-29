fn pinned_checkout_workflow(trigger: &str, revision: &str) -> String {
    format!(
        "\
name: Triage
on: {trigger}
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
        with:
          ref: {revision}
"
    )
}

fn assert_untrusted_checkout_blocks(findings: &[Finding]) {
    assert!(
        findings.iter().any(|finding| {
            finding.rule_id == RULE_UNTRUSTED_CHECKOUT && finding.severity == Severity::Critical
        }),
        "expected critical untrusted checkout, findings={findings:?}"
    );
    assert_eq!(crate::decision::derive(findings), Decision::Block);
}

fn assert_no_untrusted_checkout(findings: &[Finding]) {
    assert!(
        findings
            .iter()
            .all(|finding| finding.rule_id != RULE_UNTRUSTED_CHECKOUT),
        "unexpected untrusted checkout, findings={findings:?}"
    );
    assert_eq!(crate::decision::derive(findings), Decision::Allow);
}

fn head_serialization_composite_files(caller_ref: &str) -> Vec<SurfaceFile> {
    vec![
        SurfaceFile {
            rel: ".github/workflows/triage.yml".to_string(),
            content: format!(
                "\
name: Triage
on: pull_request_target
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/checkout-pr
        with:
          ref: {caller_ref}
"
            ),
            kind: SurfaceKind::Workflow,
        },
        SurfaceFile {
            rel: ".github/actions/checkout-pr/action.yml".to_string(),
            content: "\
name: checkout-pr
inputs:
  ref:
    required: true
runs:
  using: composite
  steps:
    - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      with:
        ref: ${{ inputs.ref }}
"
            .to_string(),
            kind: SurfaceKind::ActionMetadata,
        },
    ]
}

#[test]
fn privileged_pull_request_head_serialization_sha_blocks() {
    let findings = findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "${{ fromJSON(toJSON(github.event.pull_request.head)).sha }}",
    ));
    assert_untrusted_checkout_blocks(&findings);
}

#[test]
fn privileged_pull_request_head_serialization_ref_blocks() {
    let findings = findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "${{ fromJSON(toJSON(github.event.pull_request.head)).ref }}",
    ));
    assert_untrusted_checkout_blocks(&findings);
}

#[test]
fn privileged_pull_request_head_bracket_serialization_sha_blocks() {
    let findings = findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "${{ fromJSON(toJSON(github.event['pull_request']['head'])).sha }}",
    ));
    assert_untrusted_checkout_blocks(&findings);
}

#[test]
fn privileged_local_composite_pull_request_head_serialization_sha_blocks() {
    let files = head_serialization_composite_files(
        "${{ fromJSON(toJSON(github.event.pull_request.head)).sha }}",
    );
    assert_untrusted_checkout_blocks(&findings_for_files(&files));
}

#[test]
fn privileged_local_composite_pull_request_head_serialization_ref_blocks() {
    let files = head_serialization_composite_files(
        "${{ fromJSON(toJSON(github.event.pull_request.head)).ref }}",
    );
    assert_untrusted_checkout_blocks(&findings_for_files(&files));
}

#[test]
fn privileged_pull_request_head_tojson_object_blocks() {
    let findings = findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "${{ toJSON(github.event.pull_request.head) }}",
    ));
    assert_untrusted_checkout_blocks(&findings);
}

#[test]
fn privileged_pull_request_head_fromjson_object_blocks() {
    let findings = findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "${{ fromJSON(toJSON(github.event.pull_request.head)) }}",
    ));
    assert_untrusted_checkout_blocks(&findings);
}

#[test]
fn privileged_serialized_pull_request_base_sha_is_not_untrusted_checkout() {
    let findings = findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "${{ fromJSON(toJSON(github.event.pull_request)).base.sha }}",
    ));
    assert_no_untrusted_checkout(&findings);
}

#[test]
fn privileged_pull_request_base_sha_is_not_untrusted_checkout() {
    let findings = findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "${{ github.event.pull_request.base.sha }}",
    ));
    assert_no_untrusted_checkout(&findings);
}

#[test]
fn privileged_pull_request_head_commit_sha_is_not_untrusted_checkout() {
    let findings = findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "${{ fromJSON(toJSON(github.event.pull_request.head_commit)).sha }}",
    ));
    assert_no_untrusted_checkout(&findings);
}

#[test]
fn privileged_quoted_pull_request_head_sha_literal_is_not_untrusted_checkout() {
    let findings = findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "${{ 'github.event.pull_request.head.sha' }}",
    ));
    assert_no_untrusted_checkout(&findings);
}

#[test]
fn pull_request_head_serialization_on_pull_request_is_not_untrusted_checkout() {
    let findings = findings_for(&pinned_checkout_workflow(
        "pull_request",
        "${{ fromJSON(toJSON(github.event.pull_request.head)).sha }}",
    ));
    assert_no_untrusted_checkout(&findings);
}

#[test]
fn pull_request_head_serialization_expression_boundaries() {
    assert!(is_untrusted_ref_expression(
        "${{ fromJSON( toJSON( github.event.pull_request.head ) ).sha }}"
    ));
    assert!(is_untrusted_ref_expression(
        "${{ toJSON (github.event.pull_request.head) }}"
    ));
    assert!(is_untrusted_ref_expression(
        "${{ fromJSON(toJSON(github.event.pull_request.head)).repo }}"
    ));
    assert!(is_untrusted_ref_expression(
        "${{ (github.event.pull_request.head).ref }}"
    ));
    assert!(is_untrusted_ref_expression(
        "${{ FromJSON(ToJSON(GitHub.Event.Pull_Request.Head)).Ref }}"
    ));
    assert!(is_untrusted_ref_expression(
        "${{ toJSON(github.event['pull_request']['head']) }}"
    ));
    assert!(is_untrusted_ref_expression(
        "${{ github.event.pull_request.head)fromjson(tojson()).sha }}"
    ));
    assert!(!is_untrusted_ref_expression(
        "${{ fromJSON(toJSON(github.event.pull_request.head_ref)).sha }}"
    ));
    assert!(!is_untrusted_ref_expression(
        "${{ (github.event.pull_request.head).sha256 }}"
    ));
    assert!(!is_untrusted_ref_expression(
        "${{ (github.event.pull_request.head).label }}"
    ));
    assert!(!is_untrusted_ref_expression(
        "${{ fromJSON(toJSON(github.event.pull_request)).base.sha }}"
    ));
    assert!(!is_untrusted_ref_expression(
        "${{ 'github.event.pull_request.head.sha' }}"
    ));
}
