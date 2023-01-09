from typing import Final

from beaker import Application, ApplicationStateValue, Authorize
from beaker.decorators import (close_out, create, delete, external, opt_in,
                               update)
from pyteal import Approve, Expr, Global, Reject, TealType, abi


class ContractoriumPlatform(Application):
    """The base Algorand Contract for the Contractorium Bug Bounty Platform for Smart Contracts."""

    manager: Final[ApplicationStateValue] = ApplicationStateValue(
        stack_type=TealType.bytes, default=Global.creator_address()
    )

    @create
    def create(self) -> Expr:
        """Initialize Application state."""
        return self.initialize_application_state()

    @delete(authorize=Authorize.only(manager))
    def delete(self) -> Expr:
        """Approve delete transaction for current manager."""
        return Approve()

    @update(authorize=Authorize.only(manager))
    def update(self) -> Expr:
        """Approve update transaction for current manager."""
        return Approve()

    @opt_in
    def opt_in(self) -> Expr:
        """Reject opt_in transaction, as it is not needed in this case."""
        return Reject()

    @close_out()
    def close_out(self) -> Expr:
        """Reject close_out transaction, as it is not needed in this case."""
        return Reject()

    @external(authorize=Authorize.only(manager))
    def resign_manager(self, new_manager: abi.Address) -> Expr:
        """
        A function that accepts a new Algorand address and sets the manager to this address.

        The transaction can only succeed if the invoker is the current manager.
        """
        return self.manager.set(new_manager.get())
