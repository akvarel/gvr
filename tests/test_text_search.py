from gvr import TextSearchAssertion, VerificationVerdict, evaluate_text_search

DAYS = ("pirmdiena", "otrdiena", "trešdiena", "ceturtdiena", "piektdiena", "sestdiena", "svētdiena")


def test_plain_e_is_in_all_latvian_weekdays():
    a = TextSearchAssertion(DAYS, "e", DAYS, requested_needle="e")
    result, report = evaluate_text_search(a)
    assert result.actual_matches == DAYS
    assert report.verdict is VerificationVerdict.PASS


def test_long_e_only_sunday():
    a = TextSearchAssertion(DAYS, "ē", ("svētdiena",), requested_needle="ē")
    _, report = evaluate_text_search(a)
    assert report.verdict is VerificationVerdict.PASS


def test_historical_wrong_subset_fails():
    bad = ("trešdiena", "ceturtdiena", "piektdiena", "sestdiena")
    _, report = evaluate_text_search(TextSearchAssertion(DAYS, "e", bad, requested_needle="e"))
    assert report.verdict is VerificationVerdict.FAIL


def test_spec_mismatch_e_vs_long_e_fails_even_if_execution_self_consistent():
    _, report = evaluate_text_search(TextSearchAssertion(DAYS, "e", DAYS, requested_needle="ē"))
    assert report.verdict is VerificationVerdict.FAIL
    assert any(i.code == "SPEC_MISMATCH" for i in report.issues)


def test_required_grounding_missing_is_unknown():
    _, report = evaluate_text_search(TextSearchAssertion(DAYS, "e", DAYS))
    assert report.verdict is VerificationVerdict.UNKNOWN


def test_reverse_preserves_literal_membership_when_normalized_first():
    reversed_days = tuple(day[::-1] for day in DAYS)
    result, report = evaluate_text_search(TextSearchAssertion(DAYS, "e", DAYS, requested_needle="e", reverse=True))
    assert result.actual_matches == DAYS
    assert report.verdict is VerificationVerdict.PASS


def test_nfd_normalizes_before_reverse():
    nfd = "e\u0304"
    result, report = evaluate_text_search(TextSearchAssertion(("svētdiena",), nfd, ("svētdiena",), requested_needle="ē", reverse=True))
    assert report.verdict is VerificationVerdict.PASS
