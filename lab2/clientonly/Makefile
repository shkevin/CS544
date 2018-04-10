HOST = 64.106.46.56
PORT = 10041
MSG = "This is an example"


tar:
	tar -cxvf ${USER}-handin.tgz rsa-aes-client.py aes.py rsa.py Makefile

client:
	clear
	python rsa-aes-client.py -ip $(HOST) -p $(PORT) --m $(MSG)

server:
	clear
	python rsa-aes-server.py -ip $(HOST) -p $(PORT)

clean:
	rm -rf *.pyc