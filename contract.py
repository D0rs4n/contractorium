from typing import Final

from pyteal import *
from beaker import *


class ContractoriumPlatform(Application):
    manager: Final[ApplicationStateValue] = ApplicationStateValue(
        stack_type=TealType.bytes, default=Global.creator_address()
    )

    @create
    def create(self) -> Expr:
        return self.initialize_application_state()

    @delete(authorize=Authorize.only(manager))
    def delete(self) -> Expr:
        return Approve()

    @update(authorize=Authorize.only(manager))
    def update(self):
        return Approve()

    @opt_in
    def opt_in(self) -> Expr:
        return Reject()

    @close_out()
    def close_out(self) -> Expr:
        return Reject()

    @external(authorize=Authorize.only(manager))
    def resign_manager(self, new_manager: abi.Address) -> Expr:
        return self.manager.set(new_manager.get())