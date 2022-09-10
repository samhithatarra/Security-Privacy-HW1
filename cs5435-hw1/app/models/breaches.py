from sqlalchemy import Column, Integer, String
import hashlib

from app.models.user import SALT
from app.models.base import Base

class PlaintextBreach(Base):
    __tablename__ = "plaintext_breaches"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    password = Column(String)

class HashedBreach(Base):
    __tablename__ = "hashed_breaches"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    hashed_password = Column(String)

class SaltedBreach(Base):
    __tablename__ = "salted_breaches"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    salted_password = Column(String)
    salt = Column(String)

def create_plaintext_breach_entry(db, username, password):
    breach = PlaintextBreach(
        username=username,
        password=password,
    )
    db.add(breach)
    return breach

def create_hashed_breach_entry(db, username, hashed_password):
    breach = HashedBreach(
        username=username,
        hashed_password=hashed_password,
    )
    db.add(breach)
    return breach

def create_salted_breach_entry(db, username, salted_password, salt):
    breach = SaltedBreach(
        username=username,
        salted_password=salted_password,
        salt=salt,
    )
    db.add(breach)
    return breach

def get_breaches(db, username, password):

    plaintext_breaches = db.query(PlaintextBreach).filter_by(username=username, password=password).all()
    hashed_breaches = db.query(HashedBreach).filter_by(username=username, hashed_password=hashlib.sha256(password.encode('utf-8')).hexdigest()).all()

    # Check if the user has used this password breach of salted passwords before. 
    # If the current hash of the hash of the password is equal to the hash of the 
    # breached password using the same salt of the breach it has been breached.
    salted_breaches = [user_breaches for user_breaches in db.query(SaltedBreach).filter_by(username=username).all() if hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(user_breaches.salt), 100000).hex() == user_breaches.salted_password]

    return (plaintext_breaches, hashed_breaches, salted_breaches)


