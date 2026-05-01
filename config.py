"""
Flask app configuration
"""
import requests

DEBUG = True
SC = ";"
TEMPLATES_AUTO_RELOAD = True
DB_FILE = 'databases/records.db'
SECRET_KEY = 'This is not very secret, is it?'
CREDENTIALS_FILE = 'databases/accounts.db'
MAX_ATTEMPTS = 2 #starts counting at 0
PERM_ADMIN = 1
PERM_ENGINEER = 2
LESSON_CATALOG = {
    "Cross-site Scripting (XSS)": [".cat_coin_stock", "CatCoin stock"],
    "SQL Injection Attack": [".transactions", "Transaction search"],
    "Secure Login": [".login", "Customer login"]
}




