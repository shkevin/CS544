HOST = 127.0.0.1
PORT = 10041
MSG = "This is an example"


tar:
	-tar -cvf ${USER}-handin.tar rsa-aes-client.py rsa-aes-server.py aes.py rsa.py Makefile

client:
	python rsa-aes-client.py -ip $(HOST) -p $(PORT) --m $(MSG)

server:
	python rsa-aes-server.py -ip $(HOST) -p $(PORT)

clean:
	rm -rf *.pyc