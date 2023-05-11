FROM alpine

WORKDIR /app/tour_de_monde

COPY . .

# Install python
RUN apk update & apk add gcc libc-dev python3-dev g++

RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools

RUN pip install -r requirements.txt

ENTRYPOINT [ "python" , "app.py" ]