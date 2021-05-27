FROM python:3

WORKDIR /usr/src/app

COPY . .

RUN python3 setup.py install

CMD [ "python3", "./examples/v2/dojo_ci_cd.py" ]
