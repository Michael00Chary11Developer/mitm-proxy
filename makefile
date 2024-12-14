VENV_DIR = .venv


venv:
	python3 -m venv $(VENV_DIR)


active:
	chmod +x $(VENV_DIR)/bin/activate
	source $(VENV_DIR)/bin/activate


install:
	pip install -r requirements.txt


all: venv active install run


clean:
	rm -rf $(VENV_DIR)


run:
	mitmproxy -s end-mitm.py --listen-port 8081