FROM python:3-alpine

ADD . /app

RUN pip install -r /app/requirements.txt

ENTRYPOINT [ "python", "/app/checker.py" ]
CMD [ "" ]