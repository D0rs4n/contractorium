from pyteal import abi


class BountyProgram(abi.NamedTuple):
    """A namedtuple representing a Bounty Program on the Contractorium Platform."""

    name: abi.Field[abi.String]
    description: abi.Field[abi.String]
    verified: abi.Field[abi.Bool]
    image: abi.Field[abi.String]