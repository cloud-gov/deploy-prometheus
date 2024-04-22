from datetime import date
from datetime import datetime
import os
from sqlalchemy import create_engine
from sqlalchemy import ForeignKey
from sqlalchemy import select
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Session
from typing import List
from typing import Optional

"""
Credential Report columns:
user
arn
user_creation_time ISO 8601
password_enabled Boolean
password_last_used ISO 8601, N/A
password_last_changed ISO 8601, N/A
password_next_rotation ISO 8601
mfa_active Boolean
access_key_1_active Boolean
access_key_1_last_rotated ISO 8601, N/A
access_key_1_last_used_date ISO 8601, N/A
access_key_1_last_used_region String, N/A
access_key_1_last_used_service String, N/A
access_key_2_active Boolean
access_key_2_last_rotated ISO 8601, N/A
access_key_2_last_used_date ISO 8601, N/A
access_key_2_last_used_region String, N/
AccessKey_2_last_used_service String, N/
cert_1_active Boolean
cert_1_last_rotated ISO 8601, N/A
cert_2_active Boolean
cert_2_last_rotated ISO 8601, N/A

reference:
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
"""

keys_db = os.getenv('IAM_KEYS_DB')
user = os.getenv('IAM_KEYS_USER')
password = os.getenv('IAM_KEYS_PASSWORD')
host = os.getenv('IAM_KEYS_HOST')
port = os.getenv('IAM_KEYS_PORT')
print(f'keys_db: {keys_db}\nuser: {user}\npassword: {password}\nhost: {host}\nport: {port}\n')


class Base(DeclarativeBase):
    pass


engine = create_engine(f"postgresql://{user}:{password}@{host}:{port}/{keys_db}")
# Model for IAM_Keys, note the attributes that allow null and those that don't


class AccessKey(Base):
    __tablename__ = "AccessKey"
    id: Mapped[int] = mapped_column(primary_key=True)
    key_num: Mapped[int]
    access_key_active: Mapped[bool]
    access_key_last_rotated: Mapped[Optional[datetime]]
    access_key_last_used_date: Mapped[Optional[datetime]]
    access_key_last_used_region: Mapped[Optional[str]]
    access_key_last_used_service: Mapped[Optional[str]]
    cert_active: Mapped[bool]
    cert_last_rotated: Mapped[Optional[datetime]]
    user_id: Mapped[int] = mapped_column(ForeignKey("iam_keys.id"))
    user: Mapped["IAMKeys"] = relationship(back_populates="access_keys")

    @staticmethod
    def new_akeys_for_dict(ak_dict: dict):
        keys = []
        for key_num in [1, 2]:
            akey = AccessKey()
            akey.access_key_active = ak_dict[f'access_key_{key_num}_active']
            akey.access_key_last_rotated = ak_dict[f'access_key_{key_num}_last_rotated']
            akey.access_key_last_used_date = ak_dict[f'access_key_{key_num}_last_used_date']
            akey.access_key_last_used_region = ak_dict[f'access_key_{key_num}_last_used_region']
            akey.access_key_last_used_service = ak_dict[f'access_key_{key_num}_last_used_service']
            keys.append(akey)
        return keys


class IAMKeys(Base):
    __tablename__ = "iam_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    iam_user: Mapped[str]
    aws_account: Mapped[str]
    arn: Mapped[str] = mapped_column(unique=True)
    user_creation_time: Mapped[Optional[datetime]]
    password_enabled: Mapped[Optional[bool]]
    password_last_used: Mapped[Optional[datetime]]
    password_last_changed: Mapped[Optional[datetime]]
    password_next_rotation: Mapped[Optional[datetime]]
    mfa_active: Mapped[Optional[bool]]
    created_at: Mapped[datetime]
    updated_at: Mapped[Optional[datetime]]
    events: Mapped[List["Event"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    access_keys: Mapped[List["AccessKey"]] = relationship(back_populates="user")

    def __repr__(self) -> str:
        return f"User(id={self.id!r}, name={self.iam_user!r} )"

    @staticmethod
    def account_for_arn(arn):
        # arn:aws-us-gov:iam::account-here:user/cf-production/s3/cg-s3-some-guid-here
        arn_components = arn.split(':')
        account = ""
        if len(arn_components) > 1:
            account = arn_components[4]
        return account

    @staticmethod
    def clean_dict(keys_dict):
        for key in keys_dict.keys():
            if keys_dict[key] in ["N/A", "no_information", "not_supported"]:
                if key == "password_enabled":
                    keys_dict[key] = False
                else:
                    keys_dict[key] = None
        return keys_dict

    def user_from_dict(self, keys_dict):
        keys_dict = self.clean_dict(keys_dict)
        with (Session(engine) as session):
            user_stmt = select(IAMKeys).where(IAMKeys.arn == keys_dict['arn']).where(IAMKeys.iam_user == keys_dict['user'])
            db_user = session.execute(user_stmt)
            if not user:
                print(f"didn't find user: {keys_dict['user']}")
                new_user = IAMKeys()
                new_user.iam_user = keys_dict['user']
                new_user.aws_account = keys_dict['aws_account']
                new_user.arn = keys_dict['arn']
                new_user.user_creation_time = keys_dict['user_creation_time']
                new_user.password_enabled = keys_dict['password_enabled']
                new_user.password_last_used = keys_dict['password_last_used']
                new_user.password_last_changed = keys_dict['password_last_changed']
                new_user.password_next_rotation = keys_dict['password_next_rotation']
                new_user.mfa_active = keys_dict['mfa_active']
                new_user.created_at = datetime.now()
                new_user.updated_at = datetime.now()
                new_user.access_keys = AccessKey.new_akeys_for_dict(keys_dict)
                session.add(new_user)
                session.commit()
                db_user = new_user
        return db_user
    
    def check_key_in_db_and_update(self, user_row, key_num):
        """
            Checks to see if user is in db, and update with the user row if they are

            Args:
                user_row: User data dictionary (dict).
                key_num: Access key number (str).

            Returns:
                None
        """
        user_row = self.clean_dict(user_row)
        with Session(engine) as session:
            try:
                user_stmt = select(IAMKeys).where(IAMKeys.arn == user_row['arn']).where(IAMKeys.iam_user == user_row['user'])
                found_user = session.execute(user_stmt)
                access_key_stmt = select(AccessKey).where(IAMKeys.iam_user == found_user)\
                                  .where(AccessKey.key_num == key_num)\
                                  .where(AccessKey.access_key_active == True)\
                                  .where(AccessKey.key_num == key_num)
                access_key = session.execute(access_key_stmt)
                found_user.updated_at = date.today()
                found_user.password_enabled = user_row['password_enabled'],
                found_user.password_last_used = user_row['password_last_used'],
                found_user.password_last_changed = user_row['password_last_changed'],
                found_user.password_next_rotation = user_row['password_next_rotation'],
                found_user.mfa_active = user_row['mfa_active'],
                access_key.access_key_last_rotated = user_row[f'access_key_{key_num}_last_rotated']
                access_key.access_key_last_used_date = user_row[f'access_key_{key_num}_last_used_date'],
                access_key.access_key_last_used_region = user_row[f'access_key_{key_num}_last_used_region'],
                access_key.access_key_last_used_service = user_row[f'access_key_{key_num}_last_used_service']
                access_key.cert_active = user_row[f'cert_{key_num}_active']
                access_key.cert_last_rotated = user_row[f'cert_{key_num}_last_rotated']
                events = Event.events_for_user(found_user)
                for event in events:
                    event.cleared = True
                session.commit()
            except Exception:
                print(f'========== user not found in db! {user_row["user"]} ==========')
                session.rollback()

    def akey_for_num(self, num: int) -> AccessKey:
        with Session(engine) as session:
            stmt = select(AccessKey).where(AccessKey.key_num == num, user=self)
            access_key = session.execute(stmt)
        return access_key
        
# Event Type stores the various event types such as warning and violation

class EventType(Base):
    __tablename__ = "event_type"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_type_name: Mapped[Optional[str]]
    created_at: Mapped[datetime]
    events: Mapped[List["Event"]] = relationship(back_populates="event_type", cascade="all, delete-orphan")

    @staticmethod
    def insert_event_type(name):
        with Session(engine) as session:
            event_type_stmt = select(EventType).where(EventType.event_type_name == name)
            event_type = session.execute(event_type_stmt)
            if not event_type:
                event_type = EventType()
                event_type.event_type_name = name
                event_type.created_at = datetime.now()

                print(f"didn't find event type: {name}")
        return event_type


# The events as they happen based on IAM creds not being rotated in a
# timely manner
class Event(Base):
    __tablename__ = "event"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("iam_keys.id"))
    user: Mapped["IAMKeys"] = relationship(back_populates="events")
    event_type_id: Mapped[int] = mapped_column(ForeignKey("event_type.id"))
    event_type: Mapped["EventType"] = relationship(back_populates="events")
    access_key_num: Mapped[int]
    cleared: Mapped[bool]
    cleared_date: Mapped[Optional[datetime]]
    warning_delta: Mapped[Optional[datetime]]
    violation_delta: Mapped[Optional[datetime]]
    alert_sent: Mapped[bool]
    created_at: Mapped[datetime]

    @staticmethod
    def new_event_type_user(event_type, iam_user, access_key_num, warning_delta, violation_delta):
        event = None
        with Session(engine) as session:
            found_event_stmt = select(Event).where(Event.user == iam_user)\
                               .where(Event.access_key_num == access_key_num)\
                               .where(Event.warning_delta == warning_delta)\
                               .where(Event.violation_delta == violation_delta)
            found_event = session.execute(found_event_stmt)
            if not found_event:
                print(f"didn't find event for user: {user}")
                event = Event()
                event.user = user
                event.event_type = event_type
                event.access_key_num = access_key_num
                event.warning_delta = warning_delta
                event.violation_delta = violation_delta
                event_type.events.append(event)
                session.add(event)
                session.commit()
                event = found_event
        return event

    @staticmethod
    def all_cleared_events():
        events: List[Event]
        with Session(engine) as session:
            event_stmt = select(Event).where(Event.cleared == True)
            found_events = session.execute(event_stmt).all()
            events = [r for r in found_events]
        return events

    @staticmethod
    def all_uncleared_events():
        events: List[Event]
        with Session(engine) as session:
            stmt = select(Event).where(Event.cleared==False)
            events = session.execute(stmt).all()
        return events
    
    @staticmethod
    def events_for_user(iam_user):
        events: List[Event]
        with Session(engine) as session:
            stmt = select(Event).where(Event.user == iam_user)
            events = session.execute(stmt).all()
        return events

    # def event_exists(self, events: [Event], access_key_num: int) -> bool:
    @staticmethod
    def event_exists(self, key_num: int, iam_user: IAMKeys):
        """
        Look for an access key rotation based on key number (1 or 2) corresponding
        to the number of access keys a user might have.
        If the same event and key number are found, return the event
        An event has an event_type of warning or violation
        """
        events = self.events_for_user(iam_user)
        found_event = None
        for event in events:
            if event.access_key_num == key_num:
                found_event = event
                break
        return found_event


    @staticmethod
    def add_event_to_db(iam_user: IAMKeys, alert_type: EventType, access_key_num: int, warning_delta: datetime, violation_delta: datetime):
        with Session(engine) as session:
            event_type = EventType.insert_event_type(alert_type)
            event = Event.new_event_type_user(event_type, iam_user, access_key_num, warning_delta, violation_delta)
            event.cleared = False
            event.alert_sent = False
            session.commit()

    @staticmethod
    def update_event(event, alert_type: str, warning_delta: datetime, violation_delta: datetime):
        with Session(engine) as session:
            if alert_type:
                event_type = EventType.insert_event_type(alert_type)
                event.event_type = event_type
                event.warning_delta = warning_delta
                event.violation_delta = violation_delta
                event.cleared = False
                session.commit()
            else:
                event.cleared = True
                event.cleared_date = datetime.now()
                session.commit()

def create_tables_debug():
    Base.metadata.create_all(engine)

def create_tables():
    Base.metadata.create_all(engine)
