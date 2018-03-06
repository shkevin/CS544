HOST = 127.0.0.1
PORT = 10041
MSG = "This is an example"


tar:
	-tar -cvf ${USER}-handin.tar rsa-aes-client.py rsa-aes-server.py aes.py rsa.py Makefile

client:
	clear
	python rsa-aes-client.py -ip $(HOST) -p $(PORT) --m $(MSG)

server:
	clear
	python rsa-aes-server.py -ip $(HOST) -p $(PORT)

clean:
	rm -rf *.pyc