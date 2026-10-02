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
fn privileged_projected_event_number_refs_block() {
    for revision in [
        "refs/pull/${{ join(github.event.*.number, '') }}/head",
        "${{ format('refs/pull/{0}/merge', join(github.event.*[format('num{0}', 'ber')], '/')) }}",
        "refs/pull/${{ join((GitHub['Event']).*.NuMbEr, '') }}/head",
        "refs/pull/${{ join(fromJSON(toJSON(github.event)).*.number, '') }}/head",
        "refs/pull/${{ join(fromJSON(toJSON(github.event.*)).*.number, '') }}/head",
        "refs/pull/${{ fromJSON(toJSON(github.event.*.number))[0.5] }}/head",
        "refs/pull/${{ false || join(github.event.*.number, '') }}/head",
    ] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            revision,
        )));
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "pull_request",
            revision,
        )));
    }
}

#[test]
fn projected_event_number_controls_remain_allowed() {
    for revision in [
        "refs/pull/${{ join(github.event.*.number[0], '') }}/head",
        "refs/pull/${{ join(github.event.*[0].number, '') }}/head",
        "refs/pull/${{ join(github.event.*.missing, '') }}/head",
        "refs/pull/${{ join(github.event['*'].number, '') }}/head",
        "refs/pull/${{ join(github.event.pull_request.*.number, '') }}/head",
        "refs/pull/${{ join(github.event.repository.*.number, '') }}/head",
        "refs/pull/${{ join(github.event.*, '') }}/head",
        "refs/pull/${{ join(github.event.*.*, '') }}/head",
        "refs/pull/${{ join(github.event.*.*.number, '') }}/head",
        "refs/pull/${{ toJSON(join(github.event.*.number, '')) }}/head",
        "refs/pull/${{ true && '42' || join(github.event.*.number, '') }}/head",
        "refs/pull/${{ false && join(github.event.*.number, '') || '42' }}/head",
        "${{ format('refs/pull/{0}/head', '42', join(github.event.*.number, '')) }}",
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn privileged_projected_json_number_refs_block() {
    for revision in [
        "refs/pull/${{ join(fromJSON(format('{{\"n\":{0}}}', github.event.number)).*, '') }}/head",
        "refs/pull/${{ join(fromJSON(format('[{0}]', github.event.number)).*, '') }}/merge",
        "refs/pull/${{ join(fromJSON(format('[{{\"n\":{0}}}]', github.event.number)).*.n, '') }}/head",
        "refs/pull/${{ join(fromJSON(format('{{\"n\":[{0}]}}', github.event.number)).*[0], '') }}/head",
        "refs/pull/${{ join(fromJSON(format('[[{0}]]', github.event.number)).*.*, '') }}/head",
        "refs/pull/${{ fromJSON(toJSON(fromJSON(format('[{0}]', github.event.number)).*))[0] }}/head",
        "refs/pull/${{ join(fromJSON(format('{{\"n\":{0}}}', github.event.number)).*, '/') }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "pull_request",
            revision,
        )));
    }
}

#[test]
fn projected_json_number_controls_remain_allowed() {
    for revision in [
        "refs/pull/${{ join(fromJSON(format('[{0},42]', github.event.number)).*, '') }}/head",
        "refs/pull/${{ join(fromJSON(format('[{0}]', github.event.number)).*[0], '') }}/head",
        "refs/pull/${{ join(fromJSON(format('[{{\"n\":42,\"other\":{0}}}]', github.event.number)).*.n, '') }}/head",
        "refs/pull/${{ join(fromJSON(format('{{\"n\":[{0}]}}', github.event.number)).*, '') }}/head",
        "refs/pull/${{ join(fromJSON(format('{{\"n\":42}}', github.event.number)).*, '') }}/head",
        "refs/pull/${{ join(fromJSON(format('{{\"n\":{0}}}', 'github.event.number')).*, '') }}/head",
        "refs/pull/${{ fromJSON(format('{{\"*\":42,\"n\":{0}}}', github.event.number))['*'] }}/head",
        "refs/pull/${{ toJSON(join(fromJSON(format('[{0}]', github.event.number)).*, '')) }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn privileged_equivalent_json_number_refs_block() {
    for revision in [
        "refs/pull/${{ fromJSON(format('{0}.0', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('{0}.000', github.event.number)) }}/merge",
        "refs/pull/${{ fromJSON(format('{0}e0', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('{0}E+00', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('{0}.00e-00', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('[{0}.0]', github.event.number))[0] }}/head",
        "refs/pull/${{ fromJSON(format('{{\"number\":{0}e0}}', github.event.number)).number }}/head",
        "refs/pull/${{ join(fromJSON(format('[{0}.0]', github.event.number)), '') }}/head",
        "refs/pull/${{ toJSON(fromJSON(format('{0}.0', github.event.number))) }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn privileged_decimal_shift_number_refs_block() {
    for revision in [
        "refs/pull/${{ fromJSON(format('{0}0e-1', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('{0}000.00E-003', github.event.number)) }}/merge",
        "refs/pull/${{ fromJSON(format('[{0}00e-2]', github.event.number))[0] }}/head",
        "refs/pull/${{ join(fromJSON(format('{{\"n\":{0}0e-1}}', github.event.number)).*, '') }}/head",
        "refs/pull/${{ toJSON(fromJSON(format('{0}0e-1', github.event.number))) }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "pull_request", revision,
        )));
    }
}

#[test]
fn decimal_shift_number_controls_remain_allowed() {
    for revision in [
        "refs/pull/${{ fromJSON(format('{0}0e0', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('{0}0e-2', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('{0}0.01e-1', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('{0}0e-9999999999999999999999999999999999', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('\"{0}0e-1\"', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON('1230e-1') }}/head",
        "refs/pull/${{ fromJSON(format('{0}0e-1', 42, github.event.number)) }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn equivalent_json_number_controls_remain_allowed() {
    for revision in [
        "refs/pull/${{ fromJSON(format('{0}.5', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('{0}e1', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('{0}.0e-1', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('-{0}.0', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('0{0}.0', github.event.number)) }}/head",
        "refs/pull/${{ fromJSON(format('\"{0}.0\"', github.event.number)) }}/head",
        "refs/pull/${{ toJSON(toJSON(fromJSON(format('{0}.0', github.event.number)))) }}/head",
        "refs/pull/${{ fromJSON(format('[42,{0}.0]', github.event.number))[0] }}/head",
        "refs/pull/${{ fromJSON('42.0') }}/head",
        "refs/pull/${{ fromJSON(format('{0}.0', '42', github.event.number)) }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
    assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
        "pull_request",
        "refs/pull/${{ fromJSON(format('{0}.0', github.event.number)) }}/head",
    )));
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
fn privileged_parsed_json_number_index_coercions_block() {
    for key in ["0.5", "format('{0}', '0.5')", "false", "null", "''", "5e-1"] {
        let revision = format!(
            "refs/pull/${{{{ fromJSON(format('[{{0}}]', github.event.number))[{key}] }}}}/head"
        );
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, &revision,
            )));
        }
    }
    for trigger in ["pull_request_target", "workflow_run"] {
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            trigger,
            "refs/pull/${{ fromJSON(format('[42,{0}]', github.event.number))[true] }}/head",
        )));
    }
}

#[test]
fn parsed_json_number_index_controls_remain_allowed() {
    for key in [
        "-1",
        "'missing'",
        "'NaN'",
        "'Infinity'",
        "2147483648",
        "1.5",
    ] {
        let revision = format!(
            "refs/pull/${{{{ fromJSON(format('[{{0}}]', github.event.number))[{key}] }}}}/head"
        );
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, &revision,
            )));
        }
    }
    for trigger in ["pull_request_target", "workflow_run"] {
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            trigger,
            "refs/pull/${{ fromJSON(format('[42,{0}]', github.event.number))[0.5] }}/head",
        )));
    }
    assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
        "pull_request",
        "refs/pull/${{ fromJSON(format('[{0}]', github.event.number))[0.5] }}/head",
    )));
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
            "pull_request",
            revision,
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
    let workflow = pinned_checkout_workflow("pull_request_target", "${{ env.TARGET }}").replace(
        "jobs:",
        "env:\n  TARGET: refs/pull/${{ github.event.number }}/head\njobs:",
    );
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
        assert_no_untrusted_checkout(&findings_for_files(&head_serialization_composite_files(
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
    )
    .expect("assess checkout ref"));
    assert!(
        is_untrusted_ref_expression("${{ toJSON (github.event.pull_request.head) }}")
            .expect("assess checkout ref")
    );
    assert!(is_untrusted_ref_expression(
        "${{ fromJSON(toJSON(github.event.pull_request.head)).repo }}"
    )
    .expect("assess checkout ref"));
    assert!(
        is_untrusted_ref_expression("${{ (github.event.pull_request.head).ref }}")
            .expect("assess checkout ref")
    );
    assert!(is_untrusted_ref_expression(
        "${{ FromJSON(ToJSON(GitHub.Event.Pull_Request.Head)).Ref }}"
    )
    .expect("assess checkout ref"));
    assert!(
        is_untrusted_ref_expression("${{ toJSON(github.event['pull_request']['head']) }}")
            .expect("assess checkout ref")
    );
    assert!(is_untrusted_ref_expression(
        "${{ github.event.pull_request.head)fromjson(tojson()).sha }}"
    )
    .expect("assess checkout ref"));
    assert!(!is_untrusted_ref_expression(
        "${{ fromJSON(toJSON(github.event.pull_request.head_ref)).sha }}"
    )
    .expect("assess checkout ref"));
    assert!(
        !is_untrusted_ref_expression("${{ (github.event.pull_request.head).sha256 }}")
            .expect("assess checkout ref")
    );
    assert!(
        !is_untrusted_ref_expression("${{ (github.event.pull_request.head).label }}")
            .expect("assess checkout ref")
    );
    assert!(!is_untrusted_ref_expression(
        "${{ fromJSON(toJSON(github.event.pull_request)).base.sha }}"
    )
    .expect("assess checkout ref"));
    assert!(
        !is_untrusted_ref_expression("${{ 'github.event.pull_request.head.sha' }}")
            .expect("assess checkout ref")
    );
}

#[test]
fn pull_number_state_products_fail_as_operational_errors() {
    let operand = "github.event.action && github.event.number";
    // Eleven binary alternatives cross the renderer's 1,024-state boundary.
    let regions = format!(
        "refs/pull/{}/head",
        "${{ github.event.action && github.event.number }}".repeat(11)
    );
    let arguments = std::iter::repeat_n(operand, 11)
        .collect::<Vec<_>>()
        .join(", ");
    let formatted = format!("${{{{ format('refs/pull/{{0}}/head', {arguments}) }}}}");
    let at_limit = format!(
        "refs/pull/{}/head",
        "${{ github.event.action && github.event.number }}".repeat(10)
    );
    assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
        "workflow_run",
        &at_limit,
    )));
    for revision in [regions, formatted] {
        let error = try_scan(&[SurfaceFile {
            rel: ".github/workflows/test.yml".to_string(),
            content: pinned_checkout_workflow("workflow_run", &revision),
            kind: SurfaceKind::Workflow,
        }])
        .expect_err("an incomplete checkout assessment must fail");
        assert!(format!("{error:#}").contains("checkout ref exceeds 1024 symbolic alternatives"));
    }
}

#[test]
fn pull_number_symbolic_byte_products_fail_as_operational_errors() {
    let regions = "${{ github.event.action && github.event.number }}".repeat(10);
    let arguments = std::iter::repeat_n("github.event.action && github.event.number", 10)
        .collect::<Vec<_>>()
        .join(", ");
    for size in [919, 920, 8192] {
        let literal = "x".repeat(size);
        for revision in [
            format!("{literal}{regions}"),
            format!("{regions}{literal}"),
            format!("${{{{ format('{literal}', {arguments}) }}}}"),
        ] {
            for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
                let result = try_scan(&[SurfaceFile {
                    rel: ".github/workflows/test.yml".to_string(),
                    content: pinned_checkout_workflow(trigger, &revision),
                    kind: SurfaceKind::Workflow,
                }]);
                if size == 919 || trigger == "pull_request" {
                    assert_no_untrusted_checkout(&result.expect("bounded scan completes"));
                } else {
                    let error = result.expect_err("oversized symbolic bytes must fail");
                    assert!(format!("{error:#}")
                        .contains("checkout ref exceeds 1048576 bytes of symbolic output"));
                }
            }
        }
    }
    // Literal refs at the byte boundary remain valid without alternatives.
    assert!(
        !is_untrusted_ref_expression(&"x".repeat(1024 * 1024)).expect("literal at byte boundary")
    );
}

#[test]
fn pull_number_format_total_bytes_fail_as_operational_errors() {
    let condition = "x".repeat(3000);
    let literal = "x".repeat(1024);
    let arguments = std::iter::repeat_n("github.event.action && github.event.number", 9)
        .collect::<Vec<_>>()
        .join(", ");
    let revision = format!(
        "${{{{ format('{{0}}{{0}}{{0}}{{0}}', github.event.action == '{condition}' && '{literal}', {arguments}) }}}}"
    );
    for trigger in ["pull_request_target", "workflow_run"] {
        let error = try_scan(&[SurfaceFile {
            rel: ".github/workflows/test.yml".to_string(),
            content: pinned_checkout_workflow(trigger, &revision),
            kind: SurfaceKind::Workflow,
        }])
        .expect_err("total format output must remain bounded");
        assert!(format!("{error:#}").contains("checkout ref format exceeds"));
    }
}

#[test]
fn pull_number_yaml_trim_matches_checkout_inputs() {
    for (escape, tainted) in [
        ("\\N", false),
        ("\\x1c", false),
        ("\\x1d", false),
        ("\\x1e", false),
        ("\\x1f", false),
        (" ", true),
        ("\\t", true),
        ("\\r", true),
        ("\\n", true),
        ("\\uFEFF", true),
        ("\\u00A0", true),
        ("\\u2028", true),
        ("\\u2029", true),
    ] {
        for revision in [
            format!("\"{escape}refs/pull/${{{{ github.event.number }}}}/head\""),
            format!("\"refs/pull/${{{{ github.event.number }}}}/head{escape}\""),
        ] {
            for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
                let findings = findings_for(&pinned_checkout_workflow(trigger, &revision));
                if tainted && trigger != "pull_request" {
                    assert_untrusted_checkout_blocks(&findings);
                } else {
                    assert_no_untrusted_checkout(&findings);
                }
            }
        }
    }
}

#[test]
fn pull_number_format_length_overflow_is_an_operational_error() {
    let revision = "${{ format(format('refs/pull/{{0}}/head{0}', format('{0}{0}{0}{0}{0}{0}{0}{0}{0}{0}', '{1}{1}{1}{1}{1}{1}{1}{1}{1}{1}')), github.event.number, '') }}";
    for trigger in ["pull_request_target", "workflow_run"] {
        let error = try_scan(&[SurfaceFile {
            rel: ".github/workflows/test.yml".to_string(),
            content: pinned_checkout_workflow(trigger, revision),
            kind: SurfaceKind::Workflow,
        }])
        .expect_err("an incomplete format render must fail");
        assert!(format!("{error:#}").contains("checkout ref format exceeds"));
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            trigger,
            "${{ format(format('refs/pull/{{0}}/head{0}', format('{0}', '{1}')), github.event.number, '') }}",
        )));
    }
    assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
        "pull_request",
        revision,
    )));
}

#[test]
fn computed_workflow_run_number_indexes_resolve_before_taint() {
    assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
        "workflow_run",
        "refs/pull/${{ github.event.workflow_run.pull_requests.*[format('{0}', 'NuMbEr')] }}/head",
    )));
    for key in [
        "format('{0}', 'missing')",
        "'missing'",
        "-1",
        "format('{0}', '0_suffix')",
        "2147483648",
        "format('{0}', 'NaN')",
    ] {
        let revision = format!(
            "refs/pull/${{{{ github.event.workflow_run.pull_requests[{key}].number }}}}/head"
        );
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "workflow_run",
            &revision,
        )));
    }
    for key in [
        "format('{0}', '0')",
        "fromJSON('0')",
        "(0)",
        "0",
        "format('{0}', '0.5')",
        "true",
        "null",
    ] {
        let revision = format!(
            "refs/pull/${{{{ GitHub.Event.Workflow_Run.Pull_Requests[{key}].Number }}}}/head"
        );
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "workflow_run",
            &revision,
        )));
    }
}

#[test]
fn constant_negation_number_controls_remain_allowed() {
    for revision in [
        "refs/pull/${{ !false && '42' || github.event.number }}/head",
        "refs/pull/${{ !null && '42' || github.event.number }}/head",
        "refs/pull/${{ !0 && '42' || github.event.number }}/head",
        "refs/pull/${{ !'' && '42' || github.event.number }}/head",
        "refs/pull/${{ !!true && '42' || github.event.number }}/head",
        "refs/pull/${{ !true && github.event.number }}/head",
        "refs/pull/${{ !'false' && github.event.number }}/head",
        "refs/pull/${{ !(false || 0) && '42' || github.event.number }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn privileged_negated_number_branches_still_block() {
    for revision in [
        "refs/pull/${{ !true || github.event.number }}/head",
        "refs/pull/${{ !!github.event.number && github.event.number }}/head",
        "refs/pull/${{ !github.event.action && github.event.number }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn privileged_root_projected_number_refs_block() {
    for revision in [
        "refs/pull/${{ join(github.*.number, '') }}/head",
        "refs/pull/${{ join(GitHub.*[format('num{0}', 'ber')], '') }}/merge",
        "refs/pull/${{ join(fromJSON(toJSON(github.*)).*.number, '') }}/head",
        "refs/pull/${{ false || join(github.*.number, '') }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "pull_request",
            revision,
        )));
    }
}

#[test]
fn root_projected_number_and_hex_controls_remain_allowed() {
    for revision in [
        "refs/pull/${{ join(github.*.missing, '') }}/head",
        "refs/pull/${{ join(github['*'].number, '') }}/head",
        "refs/pull/${{ toJSON(join(github.*.number, '')) }}/head",
        "refs/pull/${{ true && '42' || join(github.*.number, '') }}/head",
        "refs/pull/${{ 0x0 && github.event.number }}/head",
        "refs/pull/${{ 0X00 && github.event.number }}/head",
        "refs/pull/${{ !!0x0 && github.event.number }}/head",
        "refs/pull/${{ 0xff || github.event.number }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
    for expression in [
        "0xff && github.event.number",
        "0x0 || github.event.number",
        "!0x0 && github.event.number",
        "'0x0' && github.event.number",
        "0xffffffffffffffff && github.event.number",
    ] {
        let revision = format!("refs/pull/${{{{ {expression} }}}}/head");
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            &revision,
        )));
    }
}

#[test]
fn pull_number_expression_nesting_fails_as_an_operational_error() {
    for inner in [
        "github.event.number",
        "github.event.number || github.event.number",
    ] {
        for depth in [256, 257] {
            let revision = format!(
                "refs/pull/${{{{ {}{inner}{} }}}}/head",
                "(".repeat(depth),
                ")".repeat(depth)
            );
            for trigger in ["pull_request_target", "workflow_run"] {
                let result = try_scan(&[SurfaceFile {
                    rel: ".github/workflows/triage.yml".into(),
                    content: pinned_checkout_workflow(trigger, &revision),
                    kind: SurfaceKind::Workflow,
                }]);
                if depth == 256 {
                    assert_untrusted_checkout_blocks(&result.expect("at nesting boundary"));
                } else {
                    assert!(format!("{:#}", result.expect_err("above nesting boundary"))
                        .contains("checkout ref exceeds 256 levels of expression nesting"));
                }
            }
        }
    }
    let revision = format!("refs/pull/${{{{ '{}' }}}}/head", "(".repeat(1024));
    assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
        "pull_request_target",
        &revision,
    )));
}

#[test]
fn privileged_nested_root_projected_number_refs_block() {
    for revision in [
        "refs/pull/${{ join(github.*.*.number, '') }}/head",
        "refs/pull/${{ join(GitHub.*.*[format('num{0}', 'ber')], '') }}/merge",
        "refs/pull/${{ false || join(github.*.*.number, '') }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "pull_request",
            revision,
        )));
    }
}

#[test]
fn nested_root_projected_number_controls_remain_allowed() {
    for revision in [
        "refs/pull/${{ join(github.*.*.missing, '') }}/head",
        "refs/pull/${{ join(github['*'].*.number, '') }}/head",
        "refs/pull/${{ join(github.*['*'].number, '') }}/head",
        "refs/pull/${{ toJSON(join(github.*.*.number, '')) }}/head",
        "refs/pull/${{ join(github.*.*.number[0], '') }}/head",
        "refs/pull/${{ join('github.*.*.number', '') }}/head",
        "refs/pull/${{ join(fromJSON('[{\"number\":42}]').*.number, '') }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn pull_number_join_bytes_are_bounded_before_materialization() {
    let separators = "github.event.action == 'a' && 'a' || github.event.action == 'b' && 'b' || github.event.action == 'c' && 'c' || 'd'";
    for delta in [-1isize, 0, 1] {
        let source = "x".repeat((262144isize + delta) as usize);
        let array_source = "x".repeat((262143isize + delta) as usize);
        let array_separators = ['a', 'b', 'c', 'd']
            .into_iter()
            .enumerate()
            .map(|(index, character)| {
                let value = format!(
                    "'{}'",
                    character.to_string().repeat((131072isize + delta) as usize)
                );
                if index == 3 {
                    value
                } else {
                    format!("github.event.action == '{index}' && {value}")
                }
            })
            .collect::<Vec<_>>()
            .join(" || ");
        for revision in [
            format!("${{{{ join('{source}', {separators}) }}}}"),
            format!("${{{{ join(fromJSON('[\"{array_source}\",\"\"]'), {separators}) }}}}"),
            format!("${{{{ join(fromJSON('[\"\",\"\",\"\"]'), {array_separators}) }}}}"),
        ] {
            let result = is_untrusted_ref_expression(&revision);
            if delta > 0 {
                assert!(
                    format!("{:#}", result.expect_err("join product exceeds budget"))
                        .contains("checkout ref exceeds 1048576 bytes of symbolic output")
                );
            } else {
                assert!(!result.expect("join product within budget"));
            }
        }
    }
    let source = "é".repeat(131072);
    for suffix in ["", "x"] {
        let revision = format!("${{{{ join('{source}{suffix}', {separators}) }}}}");
        let result = is_untrusted_ref_expression(&revision);
        if suffix.is_empty() {
            assert!(!result.expect("UTF-8 bytes at budget"));
        } else {
            assert!(
                format!("{:#}", result.expect_err("UTF-8 byte product above budget"))
                    .contains("checkout ref exceeds 1048576 bytes of symbolic output")
            );
        }
    }
}

#[test]
fn pull_number_join_alternative_count_is_preserved() {
    for count in [1024, 1025] {
        let separators = (0..count)
            .map(|index| {
                if index == count - 1 {
                    format!("'{index}'")
                } else {
                    format!("github.event.action == '{index}' && '{index}'")
                }
            })
            .collect::<Vec<_>>()
            .join(" || ");
        let revision = format!("${{{{ join('x', {separators}) }}}}");
        let result = is_untrusted_ref_expression(&revision);
        if count == 1024 {
            assert!(!result.expect("join at alternative-count boundary"));
        } else {
            assert!(format!(
                "{:#}",
                result.expect_err("above alternative-count boundary")
            )
            .contains("checkout ref exceeds 1024 symbolic alternatives"));
        }
    }
}

#[test]
fn privileged_named_root_projected_number_refs_block() {
    for revision in [
        "refs/pull/${{ join(github.*.pull_request.number, '') }}/head",
        "refs/pull/${{ join(GitHub.*[format('pull_{0}', 'request')].number, '') }}/merge",
        "refs/pull/${{ join(github.*.pull_request[format('num{0}', 'ber')], '') }}/head",
        "refs/pull/${{ false || join(github.*.pull_request.number, '') }}/head",
    ] {
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "pull_request",
            revision,
        )));
    }
}

#[test]
fn named_root_projected_number_controls_remain_allowed() {
    for revision in [
        "refs/pull/${{ join(github.*.missing.number, '') }}/head",
        "refs/pull/${{ join(github.*.pull_request.missing, '') }}/head",
        "refs/pull/${{ join(github.*.pull_requests.number, '') }}/head",
        "refs/pull/${{ join(github['*'].pull_request.number, '') }}/head",
        "refs/pull/${{ join(github.*['*'].number, '') }}/head",
        "refs/pull/${{ toJSON(join(github.*.pull_request.number, '')) }}/head",
        "refs/pull/${{ join('github.*.pull_request.number', '') }}/head",
        "refs/pull/${{ join(fromJSON('[{}]').*.pull_request.number, '') }}/head",
        "refs/pull/${{ join(fromJSON('[{\"pull_request\":{}}]').*.pull_request.number, '') }}/head",
        "refs/pull/${{ true && '42' || join(github.*.pull_request.number, '') }}/head",
        "${{ github.ref }}",
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, revision,
            )));
        }
    }
}

#[test]
fn pull_number_unary_nesting_is_bounded_before_evaluation() {
    for depth in [255, 256, 257] {
        for expression in [
            format!("{}true", "!".repeat(depth)),
            format!("{}true", "! ".repeat(depth)),
            format!("!{}true{}", "(".repeat(depth - 1), ")".repeat(depth - 1)),
            format!(
                "{}{}true{}",
                "!(".repeat(depth / 2),
                if depth % 2 == 0 { "" } else { "!" },
                ")".repeat(depth / 2)
            ),
        ] {
            let revision = format!("refs/pull/${{{{ {expression} }}}}/head");
            for trigger in ["pull_request_target", "workflow_run"] {
                let result = try_scan(&[SurfaceFile {
                    rel: ".github/workflows/triage.yml".into(),
                    content: pinned_checkout_workflow(trigger, &revision),
                    kind: SurfaceKind::Workflow,
                }]);
                if depth > 256 {
                    assert!(
                        format!("{:#}", result.expect_err("above unary nesting boundary"))
                            .contains("checkout ref exceeds 256 levels of expression nesting")
                    );
                } else {
                    assert_no_untrusted_checkout(&result.expect("within unary nesting boundary"));
                }
            }
        }
    }
}

#[test]
fn unary_number_literals_and_sibling_branches_keep_their_depth() {
    for expression in [
        format!("'{}'", "!".repeat(1024)),
        format!("'{}''{}'", "!".repeat(256), "!".repeat(256)),
        format!("{}true || {}true", "!".repeat(256), "!".repeat(256)),
        format!(
            "format('{{0}}{{1}}', {}true, {}true)",
            "!".repeat(255),
            "!".repeat(255)
        ),
        "!0xff && github.event.number".to_string(),
        "github.event.action != 'opened' && '42'".to_string(),
    ] {
        let revision = format!("refs/pull/${{{{ {expression} }}}}/head");
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            &revision,
        )));
    }
    for depth in [255, 256] {
        let inner = if depth % 2 == 0 { "true" } else { "false" };
        let revision = format!(
            "refs/pull/${{{{ {}{inner} && github.event.number }}}}/head",
            "!".repeat(depth)
        );
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "pull_request_target",
            &revision,
        )));
    }
}

#[test]
fn pull_number_access_chain_depth_is_bounded_before_evaluation() {
    for depth in [255, 256, 257] {
        for expression in [
            format!("github{}", ".a".repeat(depth)),
            format!("github{}", ".*".repeat(depth)),
            format!("github{}", "['a']".repeat(depth)),
            format!("{}github{}", "!".repeat(128), ".a".repeat(depth - 128)),
            format!(
                "{}github{}{}",
                "(".repeat(128),
                ".a".repeat(depth - 128),
                ")".repeat(128)
            ),
            format!("(github{}){}", ".a".repeat(128), ".a".repeat(depth - 129)),
            format!("fromJSON(toJSON(github)){}", ".a".repeat(depth - 2)),
            format!(
                "github{}[github{}]",
                ".a".repeat(128),
                ".a".repeat(depth - 129)
            ),
            format!("(github{} || true).a", ".a".repeat(depth - 2)),
        ] {
            let revision = format!("refs/pull/${{{{ {expression} }}}}/head");
            for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
                let result = try_scan(&[SurfaceFile {
                    rel: ".github/workflows/triage.yml".into(),
                    content: pinned_checkout_workflow(trigger, &revision),
                    kind: SurfaceKind::Workflow,
                }]);
                if depth > 256 && trigger != "pull_request" {
                    assert!(
                        format!("{:#}", result.expect_err("above access-chain boundary"))
                            .contains("checkout ref exceeds 256 levels of expression nesting")
                    );
                } else {
                    assert_no_untrusted_checkout(&result.expect("within access-chain boundary"));
                }
            }
        }
    }
}

#[test]
fn access_chain_number_literals_and_siblings_preserve_the_boundary() {
    for expression in [
        format!("'{}'", ".![]()".repeat(1024)),
        format!("'{}''{}'", ".a".repeat(256), ".a".repeat(256)),
        format!("{}0.5", "!".repeat(256)),
        format!("{}0xff", "!".repeat(256)),
        format!("{}1.25e-3{}", "(".repeat(256), ")".repeat(256)),
        format!("github{} || github{}", ".a".repeat(256), ".b".repeat(256)),
        format!(
            "format('{{0}}{{1}}', github{}, github{})",
            ".a".repeat(255),
            ".b".repeat(255)
        ),
    ] {
        let revision = format!("refs/pull/${{{{ {expression} }}}}/head");
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                trigger, &revision,
            )));
        }
    }
    for expression in [
        format!("{}github.event.number{}", "(".repeat(256), ")".repeat(256)),
        format!("github{} || github.event.number", ".a".repeat(256)),
        format!("{}false || github.event.number", "!".repeat(256)),
    ] {
        let revision = format!("refs/pull/${{{{ {expression} }}}}/head");
        for trigger in ["pull_request_target", "workflow_run"] {
            assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
                trigger, &revision,
            )));
        }
    }
}

#[test]
fn workflow_run_number_event_wildcards_preserve_children() {
    for expression in [
        "join(github.event.*.pull_requests.*.number, '')",
        "join(github.*.*.pull_requests.*.number, '')",
        "join(github.event.*['pull_requests'].*['number'], '')",
        "join(fromJSON(toJSON(github.event)).*.pull_requests.*.number, '')",
        "join(github.event.*.pull_requests.*.number, '-')",
    ] {
        let revision = format!("refs/pull/${{{{ {expression} }}}}/head");
        assert_untrusted_checkout_blocks(&findings_for(&pinned_checkout_workflow(
            "workflow_run",
            &revision,
        )));
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "pull_request",
            &revision,
        )));
    }
    for expression in [
        "join(github.event.*.pull_requests.*.missing, '')",
        "join(github.event.*.wrong.*.number, '')",
        "join(github.event.*.pull_requests.*.numbered, '')",
        "join(github.event.*.pull_requests.*.title, '')",
        "join(fromJSON('[{\"number\":42}]').*.number, '')",
        "'github.event.*.pull_requests.*.number'",
    ] {
        let revision = format!("refs/pull/${{{{ {expression} }}}}/head");
        assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
            "workflow_run",
            &revision,
        )));
    }
}

#[test]
fn number_json_growth_is_bounded_before_discarding_the_value() {
    for levels in [3, 4, 5] {
        let expression = format!(
            "{}'{}'{} && github.event.number",
            "toJSON(".repeat(levels),
            "\\".repeat(64 * 1024),
            ")".repeat(levels)
        );
        let revision = format!("refs/pull/${{{{ {expression} }}}}/head");
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            let result = try_scan(&[SurfaceFile {
                rel: ".github/workflows/triage.yml".into(),
                content: pinned_checkout_workflow(trigger, &revision),
                kind: SurfaceKind::Workflow,
            }]);
            if trigger == "pull_request" {
                assert_no_untrusted_checkout(&result.expect("ordinary trigger"));
            } else if levels == 3 {
                assert_untrusted_checkout_blocks(&result.expect("within symbolic byte limit"));
            } else {
                assert!(format!(
                    "{:#}",
                    result.expect_err("JSON exceeds byte budget before logical result")
                )
                .contains("checkout ref exceeds 1048576 bytes of symbolic output"));
            }
        }
    }
}

#[test]
fn parsed_missing_number_operands_short_circuit_as_null() {
    for missing in [
        "fromJSON('{}').missing",
        "fromJSON('{\"present\":1}').MISSING",
        "fromJSON('{}')['missing']",
        "fromJSON('{}')[format('mis{0}', 'sing')]",
        "fromJSON('[]')[0]",
        "fromJSON('[42]')[1]",
        "fromJSON('[42]')['missing']",
        "fromJSON('[42]')[-1]",
        "fromJSON('{\"child\":{}}').child.missing",
        "fromJSON('[{}]')[0].missing",
        "fromJSON('{}').missing.more",
        "fromJSON('[[]]')[0][0]",
        "fromJSON('[null]')[0]",
        "fromJSON('{\"value\":null}').value",
        "fromJSON('{\"value\":false}').value",
        "fromJSON('{\"value\":0}').value",
        "fromJSON('{\"value\":\"\"}').value",
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            for expression in [
                format!("{missing} && github.event.number"),
                format!("{missing} || '42'"),
            ] {
                let revision = format!("refs/pull/${{{{ {expression} }}}}/head");
                assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(
                    trigger, &revision,
                )));
            }
            let revision = format!("refs/pull/${{{{ {missing} || github.event.number }}}}/merge");
            let findings = findings_for(&pinned_checkout_workflow(trigger, &revision));
            if trigger == "pull_request" {
                assert_no_untrusted_checkout(&findings);
            } else {
                assert_untrusted_checkout_blocks(&findings);
            }
        }
    }
}

#[test]
fn parsed_missing_number_controls_preserve_projection_and_unknown_values() {
    for (expression, blocked) in [
        ("fromJSON('[{}]').*.missing && github.event.number", true),
        ("fromJSON('[{}]').*.missing || github.event.number", false),
        ("join(fromJSON('[{}]').*.missing, '') && github.event.number", false),
        ("join(fromJSON('[{}]').*.missing, '') || github.event.number", true),
        ("fromJSON('{}').* && github.event.number", true),
        ("fromJSON('{}').* || github.event.number", false),
        ("!fromJSON('{}').missing && github.event.number", true),
        ("fromJSON(format('{{\"number\":{0}}}', github.event.number)).number", true),
        ("fromJSON(format('[{0}]', github.event.number))[0]", true),
        ("fromJSON(format('{{\"child\":{{\"number\":{0}}}}}', github.event.number)).child.number", true),
        ("join(fromJSON(format('[{{\"number\":{0}}}]', github.event.number)).*.number, '')", true),
        ("inputs.unknown.missing && github.event.number", true),
        ("fromJSON('[42]')[inputs.index] && github.event.number", true),
        ("fromJSON('{\"present\":true}')[inputs.key] && github.event.number", true),
        ("fromJSON('{\"present\":true}')[inputs.key] || github.event.number", true),
        ("fromJSON(inputs.json).missing && github.event.number", true),
    ] {
        let revision = format!("refs/pull/${{{{ {expression} }}}}/head");
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            let findings = findings_for(&pinned_checkout_workflow(trigger, &revision));
            if blocked && trigger != "pull_request" {
                assert_untrusted_checkout_blocks(&findings);
            } else {
                assert_no_untrusted_checkout(&findings);
            }
        }
    }
}

#[test]
fn number_json_template_bracket_access_retains_taint() {
    for expression in [
        "fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', github.event.number)).selected",
        "fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', github['event']['number']))['selected']",
        "fromJSON(format('{{\"padding\":[\"number\"],\"text\":\"don''t\",\"selected\":{0}}}', github.event.number)).selected",
        "fromJSON(format('{{\"padding\":[[\"number\"]],\"selected\":{{\"numbers\":[{0}]}}}}', github.event.number)).selected.numbers[0]",
        "join(fromJSON(format('[{{\"padding\":[\"number\"],\"selected\":{0}}}]', github.event.number)).*.selected, '')",
        "fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', github.event.workflow_run.pull_requests[0].number)).selected",
        "fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', github.event.number))['selected']",
        "fromJSON('[\"number\"]')[0] && github['event']['number']",
    ] {
        let revision = format!("refs/pull/${{{{ {expression} }}}}/head");
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            let findings = findings_for(&pinned_checkout_workflow(trigger, &revision));
            if trigger == "pull_request" {
                assert_no_untrusted_checkout(&findings);
            } else {
                assert_untrusted_checkout_blocks(&findings);
            }
        }
    }
}

#[test]
fn number_json_template_bracket_controls_remain_allowed() {
    for expression in [
        "fromJSON('[\"number\"]')[0] || github.event.number",
        "fromJSON(format('{{\"padding\":[\"number\"],\"selected\":false}}', github.event.number)).selected && github.event.number",
        "fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', 42, github.event.number)).selected",
        "fromJSON(format('{{\"padding\":[\"number\"],\"selected\":\"github.event.number\"}}', github.event.number)).selected",
        "'github[''event''][''number'']'",
        "'don''t [\"number\"]' || github.event.number",
        "fromJSON(format('{{\"padding\":[\"number\"],\"selected\":null}}', github.event.number)).selected && github.event.number",
        "fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', github.event.number)).missing && github.event.number",
    ] {
        let revision = format!("refs/pull/${{{{ {expression} }}}}/merge");
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            assert_no_untrusted_checkout(&findings_for(&pinned_checkout_workflow(trigger, &revision)));
        }
    }
}

#[test]
fn number_json_template_normalization_preserves_quoted_bytes() {
    for literal in [
        r#"'["number"]'"#,
        "'github[''event''][''number'']'",
        r#"'don''t ["number"]'"#,
    ] {
        assert_eq!(normalize_bracket_property_access(literal), literal);
        let expression = format!("format({literal}, github['event']['number'])");
        assert_eq!(
            normalize_bracket_property_access(&expression),
            format!("format({literal}, github.event.number)")
        );
    }
}

#[test]
fn number_serialized_context_format_retains_identity() {
    for (expression, tainted) in [
        ("fromJSON(format('{0}', toJSON(github))).event.number", true),
        ("fromJSON(format('{0}', toJSON(github.event))).number", true),
        ("fromJSON(format('{0}', toJSON(github.event.pull_request))).number", true),
        ("fromJSON(format('{0}', toJSON(github.event.workflow_run))).pull_requests[0].number", true),
        ("fromJSON(format('{0}', toJSON(GitHub['Event'])))['pull_request']['number']", true),
        ("fromJSON(format('{0}', toJSON(github))).event[format('num{0}', 'ber')]", true),
        ("fromJSON(format('{{\"selected\":{0}}}', toJSON(github))).selected.event.number", true),
        ("fromJSON(format('{{\"padding\":[\"number\"],\"selected\":{0}}}', toJSON(github.event))).selected.number", true),
        ("join(fromJSON(format('{0}', toJSON(github.event.*), 'unused padding for the existing format bound')).*.number, '')", true),
        ("join(fromJSON(format('{0}', toJSON(github.*))).*.pull_request.number, '')", true),
        ("join(fromJSON(format('{0}', toJSON(github.event.*))).*.pull_requests.*.number, '')", true),
        ("fromJSON(fromJSON(format('{0}', toJSON(toJSON(github))))).event.number", true),
        ("fromJSON(format('{0}', join(toJSON(github), ''))).event.number", true),
        ("fromJSON(format('{0}', toJSON(fromJSON('{\"event\":{\"number\":42}}')))).event.number", false),
        ("fromJSON(format('{0}', toJSON('github.event.number')))", false),
        ("fromJSON(format('{0}', toJSON(github.event))).workflow_run.number", false),
        ("join(fromJSON(format('{0}', toJSON(github.event.*))).*.numbered, '')", false),
        ("fromJSON(format('{{\"selected\":42}}', toJSON(github.event))).selected", false),
        ("fromJSON(format('{{\"selected\":\"github.event.number\"}}', toJSON(github.event))).selected", false),
        ("fromJSON(format('{0}', toJSON(github))) && '42'", false),
        ("fromJSON(format('{0}', toJSON(github))) || github.event.number", false),
        ("fromJSON(format('{{\"text\":\"don''t [\\\"number\\\"]\",\"number\":42}}', toJSON(github.event))).number", false),
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            for suffix in ["head", "merge"] {
                let revision = format!("refs/pull/${{{{ {expression} }}}}/{suffix}");
                let findings = findings_for(&pinned_checkout_workflow(trigger, &revision));
                if tainted && trigger != "pull_request" {
                    assert_untrusted_checkout_blocks(&findings);
                } else {
                    assert_no_untrusted_checkout(&findings);
                }
            }
        }
    }
}

#[test]
fn number_access_path_bytes_are_bounded_before_discarding() {
    let sources = (0..64)
        .map(|index| format!("github.a{index:02}"))
        .collect::<Vec<_>>()
        .join(" || ");
    // 64 live paths of 12 bytes plus the property give exactly 1 MiB.
    for delta in [-1isize, 0, 1] {
        let property = "x".repeat((16372isize + delta) as usize);
        let access = format!("({sources}).{property}");
        for expression in [
            access.clone(),
            format!("!({access})"),
            format!("!({access}) && github.event.number"),
            format!("({sources})[format('{{0}}', '{property}')]"),
            format!("!(({sources})[format('{{0}}', '{property}')])"),
        ] {
            let revision = format!("${{{{ {expression} }}}}");
            let result = is_untrusted_ref_expression(&revision);
            if delta > 0 {
                assert!(
                    result.is_err(),
                    "access bytes above limit must fail before an enclosing operator discards them"
                );
                assert!(format!("{:#}", result.unwrap_err())
                    .contains("checkout ref exceeds 1048576 bytes of symbolic output"));
            } else {
                assert!(!result.expect("access paths at byte boundary remain supported"));
            }
        }
    }
}

#[test]
fn number_serialized_context_format_keeps_existing_length_error() {
    let revision =
        "refs/pull/${{ join(fromJSON(format('{0}', toJSON(github.event.*))).*.number, '') }}/head";
    for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
        let result = try_scan(&[SurfaceFile {
            rel: ".github/workflows/test.yml".into(),
            content: pinned_checkout_workflow(trigger, revision),
            kind: SurfaceKind::Workflow,
        }]);
        if trigger == "pull_request" {
            assert_no_untrusted_checkout(&result.expect("ordinary trigger"));
        } else {
            assert!(
                result.is_err(),
                "existing format-length bound must remain explicit"
            );
            assert!(format!("{:#}", result.unwrap_err()).contains("checkout ref format exceeds"));
        }
    }
}

#[test]
fn number_bracket_wildcard_selectors_match_dot_projections() {
    for (expression, tainted) in [
        ("join(github.event[*].number, '')", true),
        ("join(GitHub[ * ].number, '')", true),
        ("join(github[*][*].number, '')", true),
        (
            "join(github.event.workflow_run.pull_requests[*].number, '')",
            true,
        ),
        ("join(github.event[*].pull_requests[*].number, '')", true),
        ("join(fromJSON(toJSON(github.event))[*].number, '')", true),
        (
            "join(fromJSON(format('[{{\"n\":{0}}}]', github.event.number))[*].n, '')",
            true,
        ),
        ("join(github.event['*'].number, '')", false),
        ("join(github.event[format('{0}', '*')].number, '')", false),
        ("join(github.event[*].missing, '')", false),
        (
            "join(github.event.workflow_run.pull_requests['*'].number, '')",
            false,
        ),
        ("join(fromJSON('[{\"number\":42}]')[*].number, '')", false),
        (
            "join(fromJSON('{\"*\":{\"number\":42}}')['*'].number, '')",
            false,
        ),
        ("'github.event[*].number'", false),
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            for suffix in ["head", "merge"] {
                let revision = format!("refs/pull/${{{{ {expression} }}}}/{suffix}");
                let findings = findings_for(&pinned_checkout_workflow(trigger, &revision));
                if tainted && trigger != "pull_request" {
                    assert_untrusted_checkout_blocks(&findings);
                } else {
                    assert_no_untrusted_checkout(&findings);
                }
            }
        }
    }
}

#[test]
fn number_concrete_access_results_obey_the_byte_budget() {
    let keys = (0..64)
        .map(|bits| {
            let key = (0..6)
                .map(|bit| if bits & (1 << bit) == 0 { 'x' } else { 'X' })
                .collect::<String>();
            format!("'{key}'")
        })
        .collect::<Vec<_>>();
    let keys = keys[..63]
        .iter()
        .rev()
        .enumerate()
        .fold(keys[63].clone(), |rest, (index, key)| {
            format!("github.condition{index} && {key} || ({rest})")
        });
    for delta in [-1isize, 0, 1] {
        let value = "v".repeat((16384isize + delta) as usize);
        let access = format!("fromJSON('{{\"xxxxxx\":\"{value}\"}}')[{keys}]");
        for expression in [access.clone(), format!("!({access})")] {
            let result = is_untrusted_ref_expression(&format!("${{{{ {expression} }}}}"));
            if delta > 0 {
                assert!(
                    result.is_err(),
                    "concrete result product must exceed existing byte limit"
                );
                assert!(format!("{:#}", result.unwrap_err())
                    .contains("checkout ref exceeds 1048576 bytes of symbolic output"));
            } else {
                assert!(!result.expect("boundary remains supported"));
            }
        }
    }
}

#[test]
fn number_empty_format_arguments_do_not_clone_quadratically() {
    let arguments = std::iter::repeat_n("''", 32768)
        .collect::<Vec<_>>()
        .join(",");
    let revision = format!("${{{{ format({arguments}) }}}}");
    assert!(!is_untrusted_ref_expression(&revision).expect("unused empty args render empty"));
}

const FORK_REPOSITORY_EXPRESSIONS: &[&str] = &[
    "${{ github.event.pull_request.head.repo.full_name }}",
    "${{ GitHub['Event']['Pull_Request']['Head']['Repo']['Full_Name'] }}",
    "${{ fromJSON(toJSON(github.event.pull_request.head.repo)).full_name }}",
    "${{ fromJSON(toJSON(github.event.pull_request.head)).repo.full_name }}",
    "${{ fromJSON(toJSON(github.event.pull_request)).head.repo.full_name }}",
    "${{ fromJSON(toJSON(github.event)).pull_request.head.repo.full_name }}",
    "${{ fromJSON(toJSON(github)).event.pull_request.head.repo.full_name }}",
    "${{ format('{0}/{1}', github.event.pull_request.head.repo.owner.login, github.event.pull_request.head.repo.name) }}",
    "${{ github.event.workflow_run.head_repository.full_name }}",
    "${{ GitHub['Event']['Workflow_Run']['Head_Repository']['Full_Name'] }}",
    "${{ fromJSON(toJSON(github.event.workflow_run.head_repository)).full_name }}",
    "${{ fromJSON(toJSON(github.event.workflow_run)).head_repository.full_name }}",
    "${{ fromJSON(toJSON(github.event)).workflow_run.head_repository.full_name }}",
    "${{ fromJSON(toJSON(github)).event.workflow_run.head_repository.full_name }}",
];

fn fork_repository_workflow(trigger: &str, repository: &str, revision: Option<&str>) -> String {
    let revision = revision
        .map(|value| format!("          ref: {value}\n"))
        .unwrap_or_default();
    format!(
        "on: {trigger}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          repository: {repository}\n{revision}"
    )
}

#[test]
fn fork_repository_checkout_blocks_with_omitted_or_supplied_refs() {
    for repository in FORK_REPOSITORY_EXPRESSIONS {
        for revision in [None, Some("${{ github.head_ref }}"), Some("main")] {
            for trigger in ["pull_request_target", "workflow_run"] {
                assert_untrusted_checkout_blocks(&findings_for(&fork_repository_workflow(
                    trigger, repository, revision,
                )));
            }
            assert_no_untrusted_checkout(&findings_for(&fork_repository_workflow(
                "pull_request",
                repository,
                revision,
            )));
        }
    }
}

#[test]
fn fork_repository_checkout_trusted_inputs_remain_allowed() {
    for repository in [
        "trusted/project",
        "trusted/github.event.pull_request.head.repo.full_name",
        "trusted/github.event.workflow_run.head_repository.full_name",
        "${{ github.repository }}",
        "${{ github.event.repository.full_name }}",
        "${{ github.event.pull_request.base.repo.full_name }}",
        "${{ fromJSON(toJSON(github.event.pull_request.base.repo)).full_name }}",
        "${{ 'github.event.pull_request.head.repo.full_name' }}",
        "${{ fromJSON('{\"full_name\":\"trusted/project\"}').full_name }}",
    ] {
        for trigger in ["pull_request_target", "workflow_run", "pull_request"] {
            for revision in [None, Some("${{ github.head_ref }}"), Some("main")] {
                assert_no_untrusted_checkout(&findings_for(&fork_repository_workflow(
                    trigger, repository, revision,
                )));
                let workflow = fork_repository_workflow(trigger, "${{ env.REPOSITORY }}", revision)
                    .replace(
                        "    steps:",
                        &format!("    env:\n      REPOSITORY: {repository}\n    steps:"),
                    );
                assert_no_untrusted_checkout(&findings_for(&workflow));
            }
        }
    }
}

#[test]
fn fork_repository_checkout_env_and_composite_inputs_retain_taint() {
    for repository in FORK_REPOSITORY_EXPRESSIONS {
        for trigger in ["pull_request_target", "workflow_run"] {
            for revision in [None, Some("${{ github.head_ref }}")] {
                let workflow = fork_repository_workflow(trigger, "${{ env.REPOSITORY }}", revision)
                    .replace(
                        "    steps:",
                        &format!("    env:\n      REPOSITORY: {repository}\n    steps:"),
                    );
                assert_untrusted_checkout_blocks(&findings_for(&workflow));

                let supplied_ref = revision
                    .map(|value| format!("          ref: {value}\n"))
                    .unwrap_or_default();
                let consumed_ref = revision
                    .map(|_| "          ref: ${{ inputs.ref }}\n")
                    .unwrap_or_default();
                let files = [
                    SurfaceFile {
                        rel: ".github/workflows/test.yml".into(),
                        content: format!("on: {trigger}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/fork\n        with:\n          repository: {repository}\n{supplied_ref}"),
                        kind: SurfaceKind::Workflow,
                    },
                    SurfaceFile {
                        rel: ".github/actions/fork/action.yml".into(),
                        content: format!("name: fork\ninputs:\n  repository:\n    required: true\n  ref:\n    required: false\nruns:\n  using: composite\n  steps:\n      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n        with:\n          repository: ${{{{ inputs.repository }}}}\n{consumed_ref}"),
                        kind: SurfaceKind::ActionMetadata,
                    },
                ];
                assert_untrusted_checkout_blocks(
                    &try_scan(&files).expect("scan composite repository"),
                );
            }
        }
    }
}

#[test]
fn fork_repository_checkout_expression_errors_propagate() {
    let repository = format!("${{{{ format('{{0}}{{0}}', '{}') }}}}", "x".repeat(256));
    for revision in [None, Some("${{ github.event.pull_request.head.sha }}")] {
        let result = try_scan(&[SurfaceFile {
            rel: ".github/workflows/test.yml".into(),
            content: fork_repository_workflow("pull_request_target", &repository, revision),
            kind: SurfaceKind::Workflow,
        }]);
        assert!(
            result.is_err(),
            "repository assessment must preserve operational errors"
        );
        assert!(format!("{:#}", result.unwrap_err()).contains("checkout ref format exceeds"));
    }
}
