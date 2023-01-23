from typing import Final

from beaker import Application, ApplicationStateValue, Authorize, sandbox, consts, client
from algosdk.encoding import decode_address
from beaker.decorators import (
    close_out,
    create,
    delete,
    external,
    opt_in,
    update
)
from beaker.lib.storage import Mapping
from pyteal import (
    Approve,
    Assert,
    AssetHolding,
    AssetParam,
    Balance,
    Bytes,
    Concat,
    Expr,
    Global,
    If,
    InnerTxn,
    InnerTxnBuilder,
    Int,
    Not,
    Reject,
    Seq,
    TealType,
    Txn,
    TxnField,
    TxnType,
    abi
)

from mappings import BountyProgram
from utils.cuts import calculate_cut


class ContractoriumPlatform(Application):
    """The base Algorand Contract for the Contractorium Bug Bounty Platform for Smart Contracts."""

    manager: Final[ApplicationStateValue] = ApplicationStateValue(
        stack_type=TealType.bytes, default=Global.creator_address()
    )

    cut: Final[ApplicationStateValue] = ApplicationStateValue(
        stack_type=TealType.uint64, default=Int(9800)
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

    @external(authorize=Authorize.only(manager))
    def set_cut(self, new_cut: abi.Uint64) -> Expr:
        """
        A function that accepts a new Algorand address and sets the manager to this address.

        The transaction can only succeed if the invoker is the current manager.
        """
        return self.cut.set(new_cut.get())

    @external
    def create_bounty_program(
            self,
            name: abi.String,
            description: abi.String,
    ) -> Expr:
        """
        A method to create and store a bug bounty program on the Algorand Blockchain, using Boxes.

        It accepts a name, a list of authorized members, who can accept bounties,
        and a description of the program itself.
        """
        return Seq(
            (verified_default := abi.make(abi.Bool)).set(False),
            (new_bounty_program := BountyProgram()).set(name, description, verified_default),
            self.bounty_programs[Txn.sender()].set(new_bounty_program),
        )

    @external(authorize=Authorize.only(manager))
    def verify_program(self, program: abi.Address, *, output: BountyProgram):
        tmp_name = abi.String()
        tmp_description = abi.String()
        return Seq(
            Assert(self.bounty_programs[program].exists()),
            self.bounty_programs[Txn.sender()].store_into(output),
            (output.name.store_into(tmp_name)),
            (output.description.store_into(tmp_description)),
            (verified := abi.make(abi.Bool)).set(True),
            (modified_bounty_program := BountyProgram()).set(tmp_name, tmp_description, verified),
            self.bounty_programs[program].set(modified_bounty_program),
        )

    @external
    def create_report(self, to: abi.Address, title: abi.String, description: abi.String, *, output: abi.Uint64) -> Expr:
        """Create a report, which is represented as an Algorand Standard asset."""
        return Seq(
            Assert(self.bounty_programs[to].exists()),
            InnerTxnBuilder.Execute({
                TxnField.type_enum: TxnType.AssetConfig,
                TxnField.config_asset_total: Int(1),
                TxnField.config_asset_default_frozen: Int(0),
                TxnField.config_asset_name: Concat(title.encode()),
                TxnField.config_asset_unit_name: Bytes("BBRCntrm"),
                TxnField.config_asset_reserve: to.encode(),
                TxnField.config_asset_freeze: Txn.sender(),
                TxnField.config_asset_manager: self.address,
                TxnField.config_asset_clawback: self.address,
                TxnField.config_asset_url: description.encode(),
                TxnField.config_asset_decimals: Int(0),
            }
            ),
            output.set(InnerTxn.created_asset_id())
        )

    @external
    def close_and_pay_report(self, payment: abi.PaymentTransaction, bounty_note: abi.String) -> Expr:
        """
        Close and pay a report, this function accepts a PaymentTransaction as a parameter.

        Additionally, if the report is closed, the Asset representing the bounty will be reconfigured and transfered
        to the bounty program owner.
        Furthermore, if the PaymentTransaction's parameters are valid, the hunter will be paid.
        """
        return Seq(
            (asset_balance := AssetHolding.balance(Txn.sender(), Txn.assets[0])),
            If(Not(asset_balance.hasValue())).Then(
                Seq(
                    InnerTxnBuilder.Execute({
                        TxnField.type_enum: TxnType.Payment,
                        TxnField.receiver: Txn.sender(),
                        TxnField.amount: calculate_cut(payment.get().amount(), Int(9900)),
                        TxnField.note: Bytes("Contractorium: Not opted into Bounty asset, refunding bounty..")
                    }),
                    Approve()
                )
            ),
            If(Not(asset_balance.value() == Int(0))).Then(
                Seq(
                    InnerTxnBuilder.Execute({
                        TxnField.type_enum: TxnType.Payment,
                        TxnField.receiver: Txn.sender(),
                        TxnField.amount: calculate_cut(payment.get().amount(), Int(9900)),
                        TxnField.note: Bytes("Contractorium: Asset balance mismatch, refunding bounty..")
                    }),
                    Approve()
                )),
            (report_to := AssetParam.reserve(Txn.assets[0])),
            (report_from := AssetParam.freeze(Txn.assets[0])),
            Assert(report_to.hasValue()),
            Assert(self.bounty_programs[report_to.value()].exists()),
            Assert(report_to.value() == Txn.sender()),
            Assert(payment.get().sender() == Txn.sender()),
            Assert(payment.get().receiver() == self.address),
            InnerTxnBuilder.Execute({
                TxnField.type_enum: TxnType.Payment,
                TxnField.receiver: report_from.value(),
                TxnField.amount: calculate_cut(payment.get().amount(), self.cut.get()),
                TxnField.note: bounty_note.encode()
            }),
            InnerTxnBuilder.Execute(({
                TxnField.type_enum: TxnType.AssetTransfer,
                TxnField.xfer_asset: Txn.assets[0],
                TxnField.asset_amount: Int(1),
                TxnField.asset_receiver: report_to.value(),
                TxnField.asset_sender: self.address
            })),
            InnerTxnBuilder.Execute({
                TxnField.type_enum: TxnType.AssetConfig,
                TxnField.config_asset: Txn.assets[0],
                TxnField.config_asset_reserve: Global.zero_address(),
                TxnField.config_asset_freeze: Global.zero_address(),
                TxnField.config_asset_clawback: Global.zero_address(),
                TxnField.config_asset_manager: report_to.value(),
            }),
        )

    @external(authorize=Authorize.only(manager))
    def payday(self) -> Expr:
        """Function that will pay out a specified cut from the contract's address to the creator's address."""
        return Seq(
            InnerTxnBuilder.Execute({
                TxnField.type_enum: TxnType.Payment,
                TxnField.receiver: Global.creator_address(),
                TxnField.amount: calculate_cut(Balance(self.address), self.cut.get()),
                TxnField.note: Bytes("Payment from Contractorium")
            })
        )