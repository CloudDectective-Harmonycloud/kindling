cd ../../
mkdir -p probe/build
cd probe/build
cmake -DBUILD_DRIVER=OFF -DPROBE_VERSION=0.1.1dev ..
make
libKindlingPath="./src/libkindling.so"
if [ ! -f "$libKindlingPath" ]; then
  echo "compiler libkindling failed! exit!"

else
  mkdir -p ../../collector/docker/libso &&  cp -rf ./src/libkindling.so ../../collector/docker/libso/
  cp -rf ./src/libkindling.so /usr/lib64/
  cd ../../collector/
  sh collector-version-build.sh
  collectorPath="./docker/kindling-collector"
  if [ ! -f "$collectorPath" ]; then
    echo "compiler collector failed! exit!"
  else
    cd docker
    docker build -t kindling-collector .
    #docker build -t kindling-collector . -f DockerfileLocalProbe # if build the collector with local probe, please use this command.
  fi
fi