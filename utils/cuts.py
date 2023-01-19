from pyteal import Expr, Int, Subroutine, TealType, WideRatio

basis_point_multiplier = 100 * 100


@Subroutine(TealType.uint64)
def calculate_cut(amount: Expr, cut: Expr) -> Expr:
    """A utility function to calculate cuts for the contract."""
    return WideRatio([amount, cut], [Int(basis_point_multiplier)])
