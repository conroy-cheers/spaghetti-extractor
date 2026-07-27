from tests.test_stage_a_acceptance_calls_frames import StageAAcceptanceCallsFramesTests
from tests.test_stage_a_acceptance_control_flow import StageAAcceptanceControlFlowTests
from tests.test_stage_a_acceptance_external_environment import StageAAcceptanceExternalEnvironmentTests
from tests.test_stage_a_acceptance_final_nix import StageAAcceptanceFinalNixTests
from tests.test_stage_a_acceptance_launch import StageAAcceptanceLaunchTests


class StageARelationalAcceptanceTests(
    StageAAcceptanceLaunchTests,
    StageAAcceptanceControlFlowTests,
    StageAAcceptanceCallsFramesTests,
    StageAAcceptanceExternalEnvironmentTests,
    StageAAcceptanceFinalNixTests,
):
    """Compatibility aggregate for the explicit Nix acceptance-suite target."""


def load_tests(loader, tests, pattern):
    """The phase modules own unittest discovery; avoid running them twice."""
    return loader.suiteClass()
