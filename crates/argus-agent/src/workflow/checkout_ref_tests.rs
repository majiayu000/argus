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

#[test]
fn privileged_pull_request_number_head_ref_blocks() {
    assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "refs/pull/${{ github.event.pull_request.number }}/head",
    )));
}

#[test]
fn privileged_event_number_merge_ref_blocks() {
    assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "refs/pull/${{ github.event.number }}/merge",
    )));
}

#[test]
fn privileged_formatted_pull_number_ref_blocks() {
    assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "${{ format('refs/pull/{0}/head', github.event.pull_request.number) }}",
    )));
}

#[test]
fn privileged_workflow_run_pull_number_ref_blocks() {
    assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
        "workflow_run",
        "refs/pull/${{ github.event.workflow_run.pull_requests[0].number }}/head",
    )));
}

#[test]
fn privileged_pull_number_ref_notation_variants_block() {
    for revision in [
        "refs/pull/${{ github['event']['pull_request']['number'] }}/merge",
        "refs/pull/${{ GitHub.Event.Number }}/head",
        "${{ format( 'refs/pull/{0}/merge', github.event.workflow_run.pull_requests[2].number ) }}",
        "refs/pull/${{ github.event.workflow_run.pull_requests.*.number }}/head",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "workflow_run",
            revision,
        )));
    }
}

#[test]
fn privileged_pull_number_refs_with_empty_expressions_block() {
    for revision in [
        "refs/pull/${{ github.event.pull_request.number }}/head${{ '' }}",
        "${{ '' }}refs/pull/${{ github.event.number }}/merge",
        "refs/${{ '' }}pull/${{ github.event.workflow_run.pull_requests[0].number }}/head",
        "${{ format('refs/pull/{0}/head', github.event.pull_request.number) }}${{ '' }}",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            revision,
        )));
    }
}

#[test]
fn privileged_pull_number_format_constructions_block() {
    for revision in [
        "${{ format('refs/pull/{0}/{1}', github.event.pull_request.number, 'head') }}",
        "${{ format('refs/pull/{1}/{0}', 'merge', github.event.number) }}",
        "${{ format('{0}/{1}/{2}/{3}', 'refs', 'pull', github.event.workflow_run.pull_requests[0].number, 'head') }}",
        "${{ format('refs/pull/{1}/head', 'unused, ''quoted''', github.event.number) }}",
        "${{ 'refs/pull/' }}${{ github.event.pull_request.number }}${{ '/head' }}",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            revision,
        )));
    }
}

#[test]
fn privileged_wrapped_pull_number_refs_block() {
    for revision in [
        "refs/pull/${{ fromJSON(toJSON(github.event.pull_request.number)) }}/head",
        "refs/pull/${{ (github.event.number) }}/merge",
        "${{ format('refs/pull/{0}/head', FromJSON( ToJSON( GitHub.Event.Pull_Request.Number ) )) }}",
        "refs/pull/${{ toJSON(github.event.workflow_run.pull_requests[0].number) }}/head",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            revision,
        )));
    }
}

#[test]
fn privileged_nested_pull_number_format_refs_block() {
    for revision in [
        "${{ format('refs/pull/{0}/head', format('{0}', github.event.pull_request.number)) }}",
        "${{ format('refs/pull/{0}/{1}', github.event.number, format('{0}', 'merge')) }}",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            revision,
        )));
    }
    let mut number = "github.event.pull_request.number".to_string();
    for _ in 0..256 {
        number = format!("format('{{0}}', {number})");
    }
    assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        &format!("refs/pull/${{{{ {number} }}}}/head"),
    )));
}

#[test]
fn privileged_reconstructed_pull_number_refs_block() {
    for revision in [
        "refs/pull/${{ fromJSON(toJSON(github.event.pull_request)).number }}/head",
        "refs/pull/${{ fromJSON(toJSON(github.event)).number }}/merge",
        "refs/pull/${{ fromJSON(toJSON(github)).event.pull_request.number }}/head",
        "refs/pull/${{ fromJSON(toJSON(github.event.workflow_run.pull_requests))[0].number }}/head",
        "${{ format('refs/pull/{0}/head', fromJSON(toJSON(github.event.pull_request)).number) }}",
        "${{ fromJSON(toJSON(format('refs/pull/{0}/head', github.event.number))) }}",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            revision,
        )));
    }
}

#[test]
fn trusted_number_refs_and_literal_pull_refs_remain_allowed() {
    for revision in [
        "${{ github.event.pull_request.base.sha }}",
        "${{ github.sha }}",
        "refs/heads/${{ github.event.number }}",
        "refs/pull/${{ 'github.event.pull_request.number' }}/head",
        "refs/pull/${{ github.run_number }}/head",
        "refs/pull/${{ github.event.pull_request.number_suffix }}/head",
        "${{ format('refs/heads/{0}', github.event.pull_request.number) }}",
        "${{ format('refs/pull/{0}/head', github.run_number) }}",
        "${{ format('refs/pull/{0}/head', 'github.event.number') }}",
        "${{ format('refs/pull/{0}/head', 42, github.event.number) }}",
        "${{ 'refs/pull/github.event.number/head' }}",
        "refs/pull/${{ github.event.pull_request.number }}/head${{ 'suffix' }}",
        "refs/pull/${{ github.event.pull_request.number }}/head${{ ' ' }}",
        "${{ format('refs/pull/{0}/{1}', github.event.pull_request.number, 'head-suffix') }}",
        "${{ format('refs/pull/{1}/head', github.event.pull_request.number, 42) }}",
        "${{ format('refs/pull/{{0}}/head', github.event.pull_request.number) }}",
        "${{ 'format(''refs/pull/{0}/head'', github.event.number)' }}",
        "${{ format('refs/pull/{1}/head', join(github.event.number, ', '), 42) }}",
        "refs/pull/${{ fromJSON(toJSON('github.event.pull_request.number')) }}/head",
        "refs/pull/${{ prefixFromJSON(github.event.pull_request.number) }}/head",
        "${{ format('refs/pull/{0}/head', format('{0}', 42, github.event.number)) }}",
        "${{ fromJSON(toJSON(format('refs/pull/{0}/head', 42, github.event.number))) }}",
        "refs/pull/${{ fromJSON(toJSON('github.event.pull_request')).number }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn pull_number_refs_on_pull_request_remain_allowed() {
    for revision in [
        "refs/pull/${{ github.event.pull_request.number }}/head",
        "refs/pull/${{ github.event.number }}/merge",
        "${{ format('refs/pull/{0}/head', github.event.pull_request.number) }}",
    ] {
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "pull_request",
            revision,
        )));
    }
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
