from pwncraft.tools.v012_benchmarks import correction_benchmark, helper_variant_benchmark


def test_helper_variant_benchmark_has_120_clean_cases() -> None:
    report = helper_variant_benchmark()
    assert report["total"] == 120
    assert report["passed"] == 120


def test_correction_benchmark_has_28_clean_cases() -> None:
    report = correction_benchmark()
    assert report["total"] == 28
    assert report["passed"] == 28
