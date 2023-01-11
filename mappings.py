from pyteal import abi


class BountyProgram(abi.NamedTuple):
    name: abi.Field[abi.String]
    authorized_members: abi.Field[abi.DynamicArray[abi.Address]]
    description: abi.Field[abi.String]
