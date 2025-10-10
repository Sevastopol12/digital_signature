class Settings:
    # local
    private_storage: str = r"data/private_key.pem"
    public_storage: str = r"data/public_key.pem"
    transaction_storage: str = r"data/transaction.json"

db_settings = Settings()
