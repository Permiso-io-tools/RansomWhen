FROM python:3.10

WORKDIR /ransomwhen
COPY . .

ADD ./output /ransomwhen/output
ADD ./scenarios /ransomwhen/scenarios

RUN apt update && apt install python3-pip less -y
RUN python3 -m pip install -r requirements.txt

ENTRYPOINT ["python3", "ransomwhen.py"]