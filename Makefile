CXX = g++
CXXFLAGS = -pthread -lpcap



install-dependencies:
	sudo apt-get update
	sudo apt-get install -y libpcap-dev



all: Detection_DDoS



Detection_DDoS: DDoSdetection.cpp
	$(CXX) -o $@ $< $(CXXFLAGS)




run: Detection_DDoS
	./Detection_DDoS < DATASET.txt



clean:
	rm -f Detection_DDoS



.PHONY: all run clean