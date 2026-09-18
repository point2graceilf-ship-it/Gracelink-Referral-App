import os, secrets, hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt
from pathlib import Path

DB=os.getenv("DATABASE_URL","sqlite:///./gracelink.db")
SECRET=os.getenv("GRACELINK_SECRET","DEVELOPMENT-ONLY-CHANGE-ME")
ALG="HS256"
engine=create_engine(DB,connect_args={"check_same_thread":False} if DB.startswith("sqlite") else {})
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False); Base=declarative_base()
pwd=CryptContext(schemes=["bcrypt"],deprecated="auto")
class Org(Base):
 __tablename__="organizations"; id=Column(Integer,primary_key=True); name=Column(String,nullable=False); type=Column(String,nullable=False); city=Column(String); state=Column(String); verification_status=Column(String,default="pending"); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
class User(Base):
 __tablename__="users"; id=Column(Integer,primary_key=True); org_id=Column(Integer,ForeignKey("organizations.id")); name=Column(String); email=Column(String,unique=True,index=True); password_hash=Column(String); role=Column(String,default="staff"); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
class Property(Base):
 __tablename__="properties"; id=Column(Integer,primary_key=True); org_id=Column(Integer,ForeignKey("organizations.id")); name=Column(String); city=Column(String); state=Column(String); description=Column(Text); available_beds=Column(Integer,default=0); updated_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
class Resource(Base):
 __tablename__="resources"; id=Column(Integer,primary_key=True); org_id=Column(Integer,ForeignKey("organizations.id")); name=Column(String); category=Column(String); service_area=Column(String); description=Column(Text)
class Referral(Base):
 __tablename__="referrals"; id=Column(Integer,primary_key=True); public_id=Column(String,unique=True,index=True); sender_org_id=Column(Integer,ForeignKey("organizations.id")); receiver_org_id=Column(Integer,ForeignKey("organizations.id")); client_first_name=Column(String); client_last_initial=Column(String); preferred_area=Column(String); budget=Column(Integer); notes=Column(Text); status=Column(String,default="submitted"); consent_attested=Column(Integer,default=0); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
class Audit(Base):
 __tablename__="audit_logs"; id=Column(Integer,primary_key=True); user_id=Column(Integer); action=Column(String); object_type=Column(String); object_id=Column(String); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
Base.metadata.create_all(engine)
def db():
 s=SessionLocal()
 try: yield s
 finally:s.close()
def token(u): return jwt.encode({"sub":str(u.id),"org":u.org_id,"role":u.role,"exp":datetime.now(timezone.utc)+timedelta(minutes=60)},SECRET,algorithm=ALG)
def current_user(authorization:Optional[str]=Header(None),s:Session=Depends(db)):
 if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Sign in required")
 try: data=jwt.decode(authorization[7:],SECRET,algorithms=[ALG]); u=s.get(User,int(data["sub"]))
 except Exception: raise HTTPException(401,"Invalid or expired session")
 if not u: raise HTTPException(401,"User not found")
 return u
def audit(s,u,a,o,i): s.add(Audit(user_id=u.id,action=a,object_type=o,object_id=str(i)));s.commit()
class Register(BaseModel): organization_name:str; organization_type:str; city:str=""; state:str="FL"; name:str; email:EmailStr; password:str
class Login(BaseModel): email:EmailStr; password:str
class PropertyIn(BaseModel): name:str; city:str; state:str="FL"; description:str=""; available_beds:int=0
class ResourceIn(BaseModel): name:str; category:str; service_area:str; description:str=""
class ReferralIn(BaseModel): receiver_org_id:int; client_first_name:str; client_last_initial:str=""; preferred_area:str=""; budget:Optional[int]=None; notes:str=""; consent_attested:bool
class StatusIn(BaseModel): status:str
app=FastAPI(title="GraceLink Referral Network",version="1.2")
ENV=os.getenv("GRACELINK_ENV","development").lower()
if ENV=="production" and (SECRET=="DEVELOPMENT-ONLY-CHANGE-ME" or len(SECRET)<32): raise RuntimeError("Production requires strong GRACELINK_SECRET")
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in os.getenv("ALLOWED_ORIGINS","*").split(",")],allow_methods=["*"],allow_headers=["*"])
@app.get("/health")
def health(): return {"ok":True,"service":"GraceLink"}
@app.post("/auth/register")
def register(x:Register,s:Session=Depends(db)):
 if s.query(User).filter(User.email==x.email.lower()).first(): raise HTTPException(409,"Email already registered")
 if len(x.password)<12: raise HTTPException(400,"Password must be at least 12 characters")
 o=Org(name=x.organization_name,type=x.organization_type,city=x.city,state=x.state);s.add(o);s.flush();u=User(org_id=o.id,name=x.name,email=x.email.lower(),password_hash=pwd.hash(x.password),role="org_admin");s.add(u);s.commit();s.refresh(u);audit(s,u,"register","organization",o.id);return {"access_token":token(u),"organization_id":o.id,"role":u.role}
@app.post("/auth/login")
def login(x:Login,s:Session=Depends(db)):
 u=s.query(User).filter(User.email==x.email.lower()).first()
 if not u or not pwd.verify(x.password,u.password_hash): raise HTTPException(401,"Invalid credentials")
 return {"access_token":token(u),"role":u.role,"organization_id":u.org_id}
@app.get("/me")
def me(u=Depends(current_user),s:Session=Depends(db)):
 o=s.get(Org,u.org_id);return {"id":u.id,"name":u.name,"email":u.email,"role":u.role,"organization":{"id":o.id,"name":o.name,"type":o.type,"verification_status":o.verification_status}}
@app.get("/organizations")
def organizations(s:Session=Depends(db)): return [{"id":o.id,"name":o.name,"type":o.type,"city":o.city,"state":o.state,"verification_status":o.verification_status} for o in s.query(Org).all()]
@app.post("/properties")
def create_property(x:PropertyIn,u=Depends(current_user),s:Session=Depends(db)):
 p=Property(org_id=u.org_id,**x.model_dump());s.add(p);s.commit();s.refresh(p);return {"id":p.id}
@app.get("/housing")
def housing(city:Optional[str]=None,s:Session=Depends(db)):
 q=s.query(Property,Org).join(Org,Property.org_id==Org.id).filter(Property.available_beds>0)
 if city:q=q.filter(Property.city.ilike(f"%{city}%"))
 return [{"id":p.id,"name":p.name,"city":p.city,"state":p.state,"description":p.description,"available_beds":p.available_beds,"organization":o.name,"verification_status":o.verification_status} for p,o in q.all()]
@app.post("/resources")
def create_resource(x:ResourceIn,u=Depends(current_user),s:Session=Depends(db)):
 r=Resource(org_id=u.org_id,**x.model_dump());s.add(r);s.commit();s.refresh(r);return {"id":r.id}
@app.get("/resources")
def resources(s:Session=Depends(db)): return [{"id":r.id,"name":r.name,"category":r.category,"service_area":r.service_area,"description":r.description} for r in s.query(Resource).all()]
@app.post("/referrals")
def create_referral(x:ReferralIn,u=Depends(current_user),s:Session=Depends(db)):
 if not x.consent_attested: raise HTTPException(400,"Consent attestation required")
 rid="GL-"+datetime.now().strftime("%Y%m%d")+"-"+secrets.token_hex(3).upper();r=Referral(public_id=rid,sender_org_id=u.org_id,**x.model_dump(exclude={"consent_attested"}),consent_attested=1);s.add(r);s.commit();return {"referral_id":rid,"status":r.status}
@app.get("/referrals")
def referrals(u=Depends(current_user),s:Session=Depends(db)):
 q=s.query(Referral).filter((Referral.sender_org_id==u.org_id)|(Referral.receiver_org_id==u.org_id));return [{"referral_id":r.public_id,"receiver_org_id":r.receiver_org_id,"client_reference":f"{r.client_first_name} {r.client_last_initial}.","preferred_area":r.preferred_area,"budget":r.budget,"status":r.status} for r in q.all()]
@app.patch("/referrals/{rid}/status")
def update_status(rid:str,x:StatusIn,u=Depends(current_user),s:Session=Depends(db)):
 r=s.query(Referral).filter(Referral.public_id==rid).first()
 if not r: raise HTTPException(404,"Not found")
 if r.receiver_org_id!=u.org_id: raise HTTPException(403,"Receiving organization required")
 r.status=x.status;s.commit();return {"referral_id":rid,"status":r.status}
_static=Path(__file__).parent/"static";app.mount("/static",StaticFiles(directory=str(_static)),name="static")
@app.get("/",include_in_schema=False)
def home(): return FileResponse(str(_static/"index.html"))
