import boto3
import botocore
from core.Other.PrintOutput.PrintOutput import printOutput
def authWithAccessAndSecret(AccessKey, SecretKey, UserAgent, Service):
    session = boto3.Session(
        aws_access_key_id=AccessKey,
        aws_secret_access_key=SecretKey,
    )
    if UserAgent is None:
        return session.client(Service)
    else:
        session_config = botocore.config.Config(
            user_agent=UserAgent
        )
        return session.client(Service, config=session_config)

def authWithAccessAndSecretAndSessionToken(AccessKey, SecretKey, SessionToken, UserAgent, Service):
    session = boto3.Session(
        aws_access_key_id=AccessKey,
        aws_secret_access_key=SecretKey,
        aws_session_token=SessionToken
    )
    if UserAgent is None:
        return session.client(Service)
    else:
        session_config = botocore.config.Config(
            user_agent=UserAgent
        )
        return session.client(Service, config=session_config)


def authWithProfile(profile, userAgent, service):
    session = boto3.Session(
        profile_name=profile
    )
    if userAgent is None:
        client = session.client(service)
        return client
    else:
        session_config = botocore.config.Config(
            user_agent=userAgent
        )
        return session.client(service, config=session_config)


def authenticate(Profile, AccessKey, SecretKey, SessionToken, UserAgent, Service):
    if Profile is not None and AccessKey is not None and SecretKey is not None and SessionToken is not None:
        printOutput("Please enter either profile or creds", "failure")
        return None
    elif Profile is not None and AccessKey is None and SecretKey is None and SessionToken is None:
        return authWithProfile(Profile, UserAgent, Service)
    if Profile is None and AccessKey is not None and SecretKey is not None and SessionToken is not None:
        return authWithAccessAndSecretAndSessionToken(AccessKey, SecretKey, SessionToken, UserAgent, Service)
    if Profile is None and AccessKey is not None and SecretKey is not None and SessionToken is None:
        return authWithAccessAndSecret(AccessKey, SecretKey, UserAgent, Service)
    else:
        return None

