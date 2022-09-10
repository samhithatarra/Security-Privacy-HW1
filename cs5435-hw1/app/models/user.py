from sqlalchemy import Column, Integer, String
import hashlib

from app.models.base import Base

SALT = "8d2d"

class User(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True)
    password = Column(String)
    coins = Column(Integer)

    def get_coins(self):
        return self.coins

    def credit_coins(self, i):
        self.coins += i

    def debit_coins(self, i):
        self.coins -= i

def create_user(db, username, password):
    user = User(
        username=username,
        password=hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(SALT), 100000).hex(),
        coins=100,
    )
    db.add(user)
    return user

def get_user(db, username):
    return db.query(User).filter_by(username=username).first()


