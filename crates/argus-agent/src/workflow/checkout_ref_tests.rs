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
fn privileged_pull_number_refs_with_rendered_whitespace_block() {
    for revision in [
        "refs/pull/${{ github.event.number }}/head${{ ' ' }}",
        "refs/pull/${{ github.event.pull_request.number }}/head${{ ' ' }}",
        "${{ ' ' }}refs/pull/${{ github.event.number }}/merge",
        "${{ format(' refs/pull/{0}/head ', github.event.number) }}",
        "refs/pull/${{ github.event.number }}/head${{ '\u{feff}' }}",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
    // JavaScript's getInput trim keeps NEL, unlike Rust's str::trim.
    assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "refs/pull/${{ github.event.number }}/head${{ '\u{0085}' }}",
    )));
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
fn privileged_parsed_format_number_refs_block() {
    for revision in [
        "refs/pull/${{ fromJSON(format('{0}', github.event.pull_request.number)) }}/head",
        "${{ format('refs/pull/{0}/merge', fromJSON(format('{0}', github.event.number))) }}",
        "refs/pull/${{ FromJSON( format('{0}', GitHub.Event.Number) ) }}/head",
        "refs/pull/${{ fromJSON(format('{0}', toJSON(github.event.number))) }}/head",
        "refs/pull/${{ fromJSON(toJSON(toJSON(github.event.number))) }}/head",
        "refs/pull/${{ fromJSON(format('\"{0}\"', github.event.number)) }}/head",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            revision,
        )));
    }
}

#[test]
fn serialized_number_strings_remain_allowed() {
    for revision in [
        "refs/pull/${{ toJSON(toJSON(github.event.number)) }}/head",
        "refs/pull/${{ toJSON(format('{0}', github.event.number)) }}/head",
        "refs/pull/${{ toJSON(join(github.event.workflow_run.pull_requests.*.number, '')) }}/head",
        "refs/pull/${{ toJSON(fromJSON(toJSON(toJSON(github.event.number)))) }}/head",
        "refs/pull/${{ toJSON(fromJSON(format('\"{0}\"', github.event.number))) }}/head",
        "refs/pull/${{ fromJSON(format('{0}', '42', github.event.number)) }}/head",
        "refs/pull/${{ toJSON(false) && '42' || github.event.number }}/head",
        "refs/pull/${{ fromJSON('false') && github.event.number }}/head",
        "refs/pull/${{ fromJSON('0') && github.event.number }}/head",
        "refs/pull/${{ fromJSON('null') && github.event.number }}/head",
    ] {
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
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
fn privileged_logical_pull_number_refs_block() {
    for revision in [
        "refs/pull/${{ github.event.number || github.event.number }}/head",
        "refs/pull/${{ (github.event.number && github.event.pull_request.number) }}/merge",
        "${{ format('refs/pull/{0}/head', github.event.number || '') }}",
        "refs/pull/${{ '' || github.event.number }}/head",
        "refs/pull/${{ 0 || github.event.number }}/head",
        "refs/pull/${{ null || github.event.number }}/head",
        "refs/pull/${{ '0' && github.event.number }}/head",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            revision,
        )));
    }
}

#[test]
fn privileged_boolean_number_and_refs_block() {
    for revision in [
        "refs/pull/${{ true && github.event.number }}/head",
        "${{ format('refs/pull/{0}/merge', (true && github.event.pull_request.number)) }}",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            revision,
        )));
    }
}

#[test]
fn privileged_boolean_number_or_refs_block() {
    for revision in [
        "refs/pull/${{ false || github.event.number }}/head",
        "refs/pull/${{ fromJSON(toJSON(false)) || github.event.number }}/merge",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            revision,
        )));
    }
}

#[test]
fn privileged_conditional_number_ref_blocks() {
    for revision in [
        "refs/pull/${{ github.event.action == 'opened' && github.event.number }}/head",
        "${{ format('refs/pull/{0}/merge', github.event.action == 'opened' && github.event.pull_request.number) }}",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "{ pull_request_target: { types: [opened] } }",
            revision,
        )));
    }
}

#[test]
fn privileged_computed_pull_number_index_ref_blocks() {
    for revision in [
        "refs/pull/${{ github.event.workflow_run.pull_requests[fromJSON('0')].number }}/head",
        "${{ format('refs/pull/{0}/merge', github.event.workflow_run.pull_requests[(0)].number) }}",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "workflow_run",
            revision,
        )));
    }
}

#[test]
fn privileged_joined_pull_number_refs_block() {
    for revision in [
        "refs/pull/${{ join(github.event.workflow_run.pull_requests.*.number, '') }}/head",
        "${{ format('refs/pull/{0}/merge', join(github.event.workflow_run.pull_requests.*.number)) }}",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "workflow_run",
            revision,
        )));
    }
}

#[test]
fn privileged_joined_json_array_number_refs_block() {
    for revision in [
        "${{ join(fromJSON(format('[\"refs/pull/{0}/head\"]', github.event.pull_request.number)), '') }}",
        "${{ join(fromJSON(format('[\"refs/pull/{0}/merge\"]', github.event.number))) }}",
        "${{ join(fromJSON(format('[\"refs\",\"pull\",\"{0}\",\"head\"]', github.event.number)), '/') }}",
        "${{ join(fromJSON(format('[\"refs/pull/\",\"{0}\",\"/merge\"]', github.event.number)), '') }}",
        "${{ join(fromJSON(toJSON(fromJSON(format('[\"refs/pull/{0}/head\"]', github.event.number)))), ',') }}",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn joined_json_array_number_ref_controls_remain_allowed() {
    for revision in [
        "${{ join(fromJSON(format('[\"refs\",\"pull\",\"{0}\",\"head\"]', github.event.number)), '-') }}",
        "${{ join(fromJSON(format('[\"refs/pull/\",\"{0}\",\"/head\"]', github.event.number))) }}",
        "${{ join(fromJSON(format('[\"refs/pull/{0}/head\",\"suffix\"]', github.event.number)), '') }}",
        "${{ join(fromJSON('[\"refs/pull/github.event.number/head\"]'), '') }}",
        "${{ join(fromJSON(format('[\"refs/pull/{0}/head\"]', 42, github.event.number)), '') }}",
        "${{ toJSON(join(fromJSON(format('[\"refs/pull/{0}/head\"]', github.event.number)), '')) }}",
        "${{ join(toJSON(fromJSON(format('[\"refs/pull/{0}/head\"]', github.event.number))), '') }}",
        "${{ join(fromJSON('[]'), github.event.number) }}",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn privileged_parsed_json_number_access_refs_block() {
    for revision in [
        "refs/pull/${{ fromJSON(format('[{0}]', github.event.pull_request.number))[0] }}/head",
        "refs/pull/${{ fromJSON(format('[{0}]', github.event.number))[fromJSON('0')] }}/merge",
        "${{ fromJSON(format('[\"refs/pull/{0}/head\"]', github.event.number))[0] }}",
        "refs/pull/${{ fromJSON(format('{{\"number\":{0}}}', github.event.number)).number }}/head",
        "refs/pull/${{ fromJSON(format('{{\"number\":{0}}}', github.event.number))[format('{0}', 'number')] }}/head",
        "refs/pull/${{ fromJSON(format('{{\"pull\":[{{\"number\":{0}}}]}}', github.event.number)).pull[0].number }}/head",
        "refs/pull/${{ fromJSON(format('[[{0}]]', github.event.number))[0][0] }}/merge",
        "${{ join(fromJSON(format('{{\"refs\":[\"refs/pull/{0}/head\"]}}', github.event.number)).refs, '') }}",
        "refs/pull/${{ toJSON(fromJSON(format('[{0}]', github.event.number))[0]) }}/head",
        "refs/pull/${{ fromJSON(toJSON(fromJSON(format('{{\"number\":{0}}}', github.event.number)))).number }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn parsed_json_number_access_controls_remain_allowed() {
    for revision in [
        "${{ fromJSON('[\"refs/pull/42/head\"]')[0] }}",
        "refs/pull/${{ fromJSON('[\"github.event.number\"]')[0] }}/head",
        "refs/pull/${{ fromJSON(format('[42,{0}]', github.event.number))[0] }}/head",
        "refs/pull/${{ fromJSON(format('{{\"number\":42,\"other\":{0}}}', github.event.number)).number }}/head",
        "${{ toJSON(fromJSON(format('[\"refs/pull/{0}/head\"]', github.event.number))[0]) }}",
        "refs/pull/${{ toJSON(toJSON(fromJSON(format('[{0}]', github.event.number))[0])) }}/head",
        "refs/pull/${{ toJSON(fromJSON(format('[\"{0}\"]', github.event.number))[0]) }}/head",
        "refs/pull/${{ fromJSON('[null]')[0] }}/head",
        "refs/pull/${{ fromJSON('[false]')[0] && github.event.number }}/head",
        "refs/pull/${{ toJSON(fromJSON(format('[{0}]', github.event.number)))[0] }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn privileged_unknown_logical_number_outcomes_block() {
    for revision in [
        "refs/pull/${{ github.event.action != 'opened' && '42' || github.event.number }}/head",
        "refs/pull/${{ (github.event.action == 'opened' && github.event.number) || '42' }}/merge",
        "refs/pull/${{ (github.event.action == 'opened' || '') && github.event.number }}/head",
        "${{ format('refs/pull/{0}/head', github.event.action != 'opened' && '42' || github.event.number) }}",
        "refs/pull/${{ fromJSON(toJSON(github.event.action != 'opened' && '42' || github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('[{0}]', github.event.action != 'opened' && '42' || github.event.number))[0] }}/head",
        "${{ join(fromJSON(format('[\"refs/pull/{0}/head\"]', github.event.action != 'opened' && '42' || github.event.number)), '') }}",
        "refs/pull/${{ github.event.action == 'opened' && github.event.number || (github.event.action != 'opened' && '42') }}/head",
    ] {
        for trigger in ["{ pull_request_target: { types: [opened] } }", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn unknown_logical_number_controls_remain_allowed() {
    for revision in [
        "refs/pull/${{ github.event.action != 'opened' && '42' || '43' }}/head",
        "refs/pull/${{ (github.event.action != 'opened' && '42' || '') && false && github.event.number }}/head",
        "refs/pull/${{ (github.event.action != 'opened' && '42' || '43') || github.event.number }}/head",
        "refs/pull/${{ (github.event.action != 'opened' && false) && github.event.number }}/head",
        "refs/pull/${{ toJSON(github.event.action != 'opened' && '42' || format('{0}', github.event.number)) }}/head",
        "${{ format('refs/pull/{0}/head', '42', github.event.action != 'opened' && '43' || github.event.number) }}",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn privileged_computed_event_number_selectors_block() {
    for revision in [
        "refs/pull/${{ github.event[format('num{0}', 'ber')] }}/head",
        "refs/pull/${{ github.event.pull_request[format('{0}', 'number')] }}/merge",
        "refs/pull/${{ GitHub.Event[format('NUM{0}', 'BER')] }}/head",
        "refs/pull/${{ github[format('{0}', 'event')][format('num{0}', 'ber')] }}/head",
        "refs/pull/${{ fromJSON(toJSON(github.event))[format('num{0}', 'ber')] }}/head",
        "refs/pull/${{ github.event[format('pull_{0}', 'request')][format('num{0}', 'ber')] }}/head",
        "refs/pull/${{ github.event.workflow_run[format('pull_{0}', 'requests')][fromJSON('0')][format('num{0}', 'ber')] }}/head",
        "refs/pull/${{ GitHub.Event.Workflow_Run[format('PULL_{0}', 'REQUESTS')][0][format('NUM{0}', 'BER')] }}/head",
        "${{ format('refs/pull/{0}/head', github.event[github.event.action != 'opened' && 'other' || format('num{0}', 'ber')]) }}",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn computed_event_number_selector_controls_remain_allowed() {
    for revision in [
        "refs/pull/${{ github.event[format('num{0}', 'ber_suffix')] }}/head",
        "refs/pull/${{ github.event.repository[format('num{0}', 'ber')] }}/head",
        "refs/pull/${{ github.event[format('num {0}', 'ber')] }}/head",
        "refs/pull/${{ github.event[format('number{0}', '()')] }}/head",
        "refs/pull/${{ 'github.event'[format('num{0}', 'ber')] }}/head",
        "refs/pull/${{ fromJSON('{\"number\":42}')[format('num{0}', 'ber')] }}/head",
        "refs/pull/${{ toJSON(toJSON(github.event[format('num{0}', 'ber')])) }}/head",
        "refs/pull/${{ github.event['other' || format('num{0}', 'ber')] }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
    for revision in [
        "refs/pull/${{ github.event.action != 'opened' && '42' || github.event.number }}/head",
        "refs/pull/${{ github.event[format('num{0}', 'ber')] }}/head",
    ] {
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "pull_request", revision,
        )));
    }
}

#[test]
fn privileged_computed_number_ref_templates_block() {
    assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "${{ format(format('{0}', 'refs/pull/{0}/head'), github.event.pull_request.number) }}",
    )));
}

#[test]
fn falsy_number_ref_conditions_remain_allowed() {
    for condition in ["0", "-0", "0.0", "0e2", "null"] {
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            &format!("refs/pull/${{{{ {condition} && github.event.number }}}}/head"),
        )));
    }
    assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        "refs/pull/${{ 42 || github.event.number }}/head",
    )));
}

#[test]
fn privileged_composite_number_refs_block() {
    for revision in [
        "refs/pull/${{ github.event.number }}/head",
        "${{ 'refs/pull/' }}${{ github.event.number }}${{ '/head' }}",
    ] {
        for expression in [
            "${{ inputs.ref }}",
            "${{ inputs.ref || github.sha }}",
            "${{ format('{0}', inputs.ref) }}",
        ] {
            let mut files = head_serialization_composite_files(revision);
            files[1].content = files[1].content.replace("${{ inputs.ref }}", expression);
            assert_untrusted_checkout_blocks(&findings_for_files(&files));
        }
    }
}

#[test]
fn privileged_env_number_ref_blocks() {
    let workflow = pinned_checkout_workflow("pull_request_target", "${{ env.TARGET }}")
        .replace("jobs:", "env:\n  TARGET: refs/pull/${{ github.event.number }}/head\njobs:");
    assert_untrusted_checkout_blocks(&findings_for(&workflow));
}

#[test]
fn trusted_composite_number_refs_remain_allowed() {
    for revision in [
        "refs/heads/${{ github.event.number }}",
        "refs/pull/${{ 'github.event.number' }}/head",
        "refs/pull/${{ github.event.number }}/head${{ 'suffix' }}",
        "refs/pull/{${{ github.event.number }}}/head",
        "refs/pull/'${{ github.event.number }}'/head",
    ] {
        assert_no_untrusted_checkout(&findings_for_files(
            &head_serialization_composite_files(revision),
        ));
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
        "refs/pull/${{ github.event.number && '42' }}/head",
        "refs/pull/${{ '42' || github.event.number }}/head",
        "refs/pull/${{ 'github.event.number || github.event.number' }}/head",
        "refs/pull/${{ false && github.event.number }}/head",
        "refs/pull/${{ true || github.event.number }}/head",
        "refs/pull/${{ 'false' || github.event.number }}/head",
        "refs/pull/${{ 'false' && '42' }}/head",
        "refs/pull/${{ github.event.number }}/head${{ false }}",
        "${{ format('refs/pull/{0}/head{1}', github.event.number, false) }}",
        "refs/pull/${{ github.event.action == 'opened' && '42' }}/head",
        "refs/pull/${{ github.event.number && github.event.action == 'opened' }}/head",
        "refs/pull/${{ github.event.action == 'opened' && github.event.number && '42' }}/head",
        "refs/pull/${{ 'github.event.workflow_run.pull_requests[fromJSON(''0'')].number' }}/head",
        "refs/pull/${{ github.event.workflow_run.pull_requests[fromJSON('0')].title }}/head",
        "refs/pull/${{ join('github.event.workflow_run.pull_requests.*.number', '') }}/head",
        "refs/pull/${{ join('42', github.event.number) }}/head",
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
