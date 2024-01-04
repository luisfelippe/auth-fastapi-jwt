from datetime import datetime, timedelta
import hashlib
from fastapi import status
from fastapi.exceptions import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext
from jose import jwt, JWTError
from decouple import config
from app.db.models import UserModel
from app.schemas import User


SECRET_KEY = config('SECRET_KEY')
ALGORITHM = config('ALGORITHM')

crypt_context = CryptContext(schemes=['sha256_crypt'])


class UserUseCases:
    """
    Classe que define os casos de usos relacionados ao usuário
    """
    def __init__(self, db_session: Session):
        self.db_session = db_session

    def __create_access_token(self, user: User, expires_in: int = 1):
        exp = datetime.utcnow() + timedelta(hours=expires_in)

        payload = {
            'sub': user.username,
            'exp': exp,
            'ttn': 'ACCESS'
        }

        access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        return access_token

    def __create_refresh_token(self, user: User, expires_in: int = 12):
        exp = datetime.utcnow() + timedelta(hours=expires_in)

        payload = {
            'sub': user.username,
            'exp': exp,
            'ttn': 'REFRESH'
        }

        refresh_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        return refresh_token

    def __create_user_finger_print(self, user: User):
        user_data = f"{user.username}{user.password}{datetime.utcnow()}"
        fingerprint = hashlib.sha256(user_data.encode()).hexdigest()

        return fingerprint

    async def user_register(self, user: User):
        """
        Método que realiza o registro de um usuário
        """
        user_model = UserModel(
            username=user.username,
            password=crypt_context.hash(user.password)
        )

        try:
            self.db_session.add(user_model)
            self.db_session.commit()
        except IntegrityError as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='User already exists'
            ) from err

    async def user_login(self, user: User):
        """
        Método destinado a autenticação de um usuário
        """
        user_on_db = self.db_session.query(UserModel).filter_by(username=user.username).first()

        if user_on_db is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Invalid username or password'
            )

        if not crypt_context.verify(user.password, user_on_db.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Invalid username or password'
            )

        access_token = self.__create_access_token(user)
        refresh_token = self.__create_refresh_token(user)
        user_finger_print = self.__create_user_finger_print(user)

        #TODO salvar os tokens em uma base de cache tipo o REDIS usando como chave o user_finger_print

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user_finger_print': user_finger_print
        }

    async def verify_token(self, access_token):
        """
        Método destinado a verificar a validade de um determinado token
        """
        try:
            data = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError as err:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Invalid access token'
            ) from err

        user_on_db = self.db_session.query(UserModel).filter_by(username=data['sub']).first()

        if user_on_db is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Invalid access token'
            )
