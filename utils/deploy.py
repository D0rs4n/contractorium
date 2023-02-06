from algosdk import algod
from beaker import client, sandbox

from contract import ContractoriumPlatform

algod_address = ""
algod_token = ""


def deploy():
    """A Simple subroutine to deploy the Contractorium contract to Algorand."""
    algod_client = algod.AlgodClient(algod_token, algod_address)
    app_client = client.ApplicationClient(
        # Get sandbox algod client
        client=algod_client,
        # Instantiate app with the program version (default is MAX_TEAL_VERSION)
        app=ContractoriumPlatform(),
        # Get acct from sandbox and pass the signer
        signer=sandbox.get_accounts()[0].signer,
    )

    # Deploy the app on-chain
    app_id, app_addr, txid = app_client.create()
    print(
        f"""Deployed app in txid {txid}
        App ID: {app_id}
        Address: {app_addr}
        """
    )


if __name__ == "__main__":
    deploy()
