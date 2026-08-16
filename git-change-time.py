import datetime
import zoneinfo
import random

pacific_tz = zoneinfo.ZoneInfo("America/Los_Angeles")
now = datetime.datetime.now(pacific_tz)
today_date = now.date()

def is_work_time(date_bytes):
    timestamp_str, _ = date_bytes.decode("utf-8").split(" ")
    dt = datetime.datetime.fromtimestamp(int(timestamp_str), tz=datetime.timezone.utc)
    dt_pacific = dt.astimezone(pacific_tz)
    return dt_pacific.weekday() < 5 and 8 <= dt_pacific.hour < 17

def standard_filter(date_bytes):
    timestamp_str, offset_str = date_bytes.decode("utf-8").split(" ")
    dt = datetime.datetime.fromtimestamp(int(timestamp_str), tz=datetime.timezone.utc)
    dt_pacific = dt.astimezone(pacific_tz)
    
    if is_work_time(date_bytes):
        if today_date.weekday() < 5 and dt_pacific.date() == today_date:
            rand_hour = 7
        else:
            rand_hour = random.randint(18, 23)
            
        rand_minute = random.randint(0, 59)
        rand_second = random.randint(0, 59)
        dt_pacific = dt_pacific.replace(hour=rand_hour, minute=rand_minute, second=rand_second)

    if dt_pacific > now:
        dt_pacific = now
        
    new_timestamp = int(dt_pacific.timestamp())
    return f"{new_timestamp} {offset_str}".encode("utf-8")

commit.author_date = standard_filter(commit.author_date)
commit.committer_date = standard_filter(commit.committer_date)
