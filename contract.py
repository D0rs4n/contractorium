from typing import Final

from beaker import Application, ApplicationStateValue, Authorize
from beaker.decorators import (close_out, create, delete, external, opt_in,
                               update)
from beaker.lib.storage import Mapping
from pyteal import (Approve, Assert, Expr, Global, Int, Reject, Seq, TealType,
                    Txn, abi)

from mappings import BountyProgram


class ContractoriumPlatform(Application):
    """The base Algorand Contract for the Contractorium Bug Bounty Platform for Smart Contracts."""

    manager: Final[ApplicationStateValue] = ApplicationStateValue(
        stack_type=TealType.bytes, default=Global.creator_address()
    )

    bounty_programs = Mapping(abi.Address, BountyProgram)

    MaxMembers = Int(1000)
    MinimumBalance = Int(2500)

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

    @external
    def create_bounty_program(
            self,
            name: abi.String,
            authorized_members: abi.DynamicArray[abi.Address],
            description: abi.String,
    ) -> Expr:
        """
        A method to create and store a bug bounty program on the Algorand Blockchain, using Boxes.

        It accepts a name, a list of authorized members, who can accept bounties,
        and a description of the program itself.
        """
        return Seq(
            (new_bounty_program := BountyProgram()).set(name, authorized_members, description),
            self.bounty_programs[Txn.sender()].set(new_bounty_program),
        )

    @external
    def set_authorized_members(
            self,
            new_authorized_members: abi.DynamicArray[abi.Address],
            *,
            output: BountyProgram
    ) -> Expr:
        """
        A method to update the members who can accept bounties.

        Note, that only the program creator can modify this.
        """
        tmp_name = abi.String()
        tmp_description = abi.String()
        return Seq(
            Assert(self.bounty_programs[Txn.sender()].exists()),
            self.bounty_programs[Txn.sender()].store_into(output),
            (output.name.store_into(tmp_name)),
            (output.description.store_into(tmp_description)),
            (modified_bounty_program := BountyProgram()).set(tmp_name, new_authorized_members, tmp_description),
            self.bounty_programs[Txn.sender()].set(modified_bounty_program),
        )
