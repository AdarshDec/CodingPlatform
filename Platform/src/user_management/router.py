from fastapi import APIRouter, Depends, HTTPException
from odmantic import AIOEngine
from Platform.src.user_management.models import User 
from Platform.src.user_management.schemas import UserCreate, UserLogin, UserOut
from Platform.src.user_management.services import create_user, authenticate_user, email_service
from Platform.src.core.dependencies import engine_dep
from Platform.src.user_management.utils import hash_password, generate_salt, generate_token, decode_token
from Platform.src.user_management.exceptions import UserAlreadyVerifiedException, UserNotFoundException, EmailServiceException

router = APIRouter(prefix="/users", tags=["users"])

@router.post("/register", response_model=UserOut)
async def register(user: UserCreate, engine: AIOEngine = Depends(engine_dep)):
    new_user = await create_user(user, engine)
    user_dict = new_user.model_dump() if hasattr(new_user, "model_dump") else new_user.__dict__
    user_dict["_id"] = str(new_user.id)
    return user_dict

@router.post("/login")
async def login(user: UserLogin, engine: AIOEngine = Depends(engine_dep)):
    return await authenticate_user(user, engine)

@router.post("/register")
async def register_user(user: UserCreate, engine: AIOEngine=Depends(engine_dep)):
    existing = await engine.find_one({'email':user.email})
    if existing:
        raise UserAlreadyVerifiedException
    salt = generate_salt()
    hashed_password = hash_password(user.password, salt)
    user_data = user.model_dump()
    new_user = User(**user_data, hashed_password=hashed_password, is_verified=False)
    await engine.save(new_user)
    token = generate_token({'sub':user.email})
    try:
        await email_service.send_verification_email(user.email, token)
    except:
        raise EmailServiceException


    return {"message": "Please check your email to verify your account"}

@router.get("/verify-email")
async def verify_email(token: str, engine: AIOEngine = Depends(engine_dep)):
    payload = decode_token(token)
    email = payload.get("sub")
    user = await engine.find_one(User, User.email==email)
    if not user:
        raise UserNotFoundException
    if user.is_verifed:
        return {"message": "Email is already verified"}
    user.is_verified = True
    await engine.save(user)
    return {"message":"Email verified"}

