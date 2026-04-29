"""
Flask app configuration
"""
import requests

DEBUG = True
SC = ";"
TEMPLATES_AUTO_RELOAD = True
DB_FILE = './instance/var/db/not_so_secure_database.db'
SECRET_KEY = 'This is not very secret, is it?'
CREDENTIALS_FILE = 'databases/accounts.db'
LESSON_CATALOG = {
    "Cross-site Scripting (XSS)": [".cat_coin_stock", "CatCoin stock"],
    "SQL Injection Attack": [".transactions", "Transaction search"],
    "Secure Login": [".login", "Customer login"]
}




