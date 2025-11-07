set -e 

# in docker
# cd /vllm-workspace/vllm/Mooncake-magik


# copy cache
# cp -r ../vllm-magik/mooncake_deps/yalantinglibs thirdparties/
# mkdir -p thirdparties
# cd thirdparties/
# git clone https://github.com/alibaba/yalantinglibs.git


# apt install screen -y
# git submodule update --init

# install go manual and add go env to .bashrc

install_go_env(){
  cd /vllm-workspace/vllm/vllm-magik/mooncake_deps
  tar -C /usr/local -xzf /vllm-workspace/vllm/vllm-magik/mooncake_deps/go1.23.8.linux-amd64.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  echo "export GOPROXY='https://goproxy.cn'" >> ~/.bashrc
  source ~/.bashrc
  go version
}

# install deps.sh
# cd /vllm-workspace/vllm/vllm-magik/mooncake_deps/Mooncake-magik && bash dependencies.sh
# cd /vllm-workspace/vllm/Mooncake-magik
# bash dependencies_with_cache.sh


# # cmake   -DPYBIND11_FINDPYTHON=OFF   -DCMAKE_BUILD_TYPE=Debug   -DCMAKE_INSTALL_PREFIX="/opt/mooncake"   -DBUILD_SHARED_LIBS=ON   -DBUILD_UNIT_TESTS=OFF   -DBUILD_EXAMPLES=ON           -DUSE_HTTP=ON   -DUSE_REDIS=ON   -DUSE_CUDA=OFF   -DUSE_ETCD=ON   -DWITH_STORE=ON   -DSTORE_USE_ETCD=ON   -S. -Bbuild -GNinja &&   cmake --build build --target install
# cmake   -DPYBIND11_FINDPYTHON=OFF   -DCMAKE_BUILD_TYPE=Release   -DCMAKE_INSTALL_PREFIX="/opt/mooncake"   -DBUILD_SHARED_LIBS=ON   -DBUILD_UNIT_TESTS=OFF   -DBUILD_EXAMPLES=ON           -DUSE_HTTP=ON   -DUSE_REDIS=ON   -DUSE_CUDA=OFF   -DUSE_ETCD=ON   -DWITH_STORE=ON   -DSTORE_USE_ETCD=ON   -S. -Bbuild -GNinja &&   cmake --build build --target install


cd /vllm-workspace/vllm/vllm-magik/mooncake_deps/Mooncake-magik/
#sed time
sed -E -i "s/[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}/$(date +%Y_%m_%d_%H_%M_%S)/g" mooncake-store/src/master.cpp
sed -E -i "s/[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}/$(date +%Y_%m_%d_%H_%M_%S)/g" mooncake-store/src/pybind_client.cpp

rm -rf build && cmake \
    -DPYBIND11_FINDPYTHON=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="/opt/mooncake" \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_UNIT_TESTS=ON \
    -DBUILD_EXAMPLES=ON \
    -DUSE_HTTP=ON \
    -DUSE_REDIS=ON \
    -DUSE_CUDA=OFF \
    -DUSE_ETCD=ON \
    -DWITH_STORE=ON \
    -DSTORE_USE_ETCD=ON \
    -S. -Bbuild -GNinja && \
    cmake --build build --target install

rm -rf build && cmake \
    -DPYBIND11_FINDPYTHON=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="/opt/mooncake" \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_UNIT_TESTS=ON \
    -DBUILD_EXAMPLES=ON \
    -DUSE_HTTP=ON \
    -DUSE_REDIS=ON \
    -DUSE_CUDA=OFF \
    -DUSE_ETCD=ON \
    -DWITH_STORE=ON \
    -DSTORE_USE_ETCD=ON \
    -S. -Bbuild -GNinja && \
    cmake --build build --target install

# find build -name "libmooncake_store.*"

echo -e "cp build/mooncake-store/src/libmooncake_store.so /opt/mooncake/lib/"
cp build/mooncake-store/src/libmooncake_store.so /opt/mooncake/lib/

# echo -e "cp build/mooncake-common/src/libmooncake_common.so /opt/mooncake/lib/"
cp build/mooncake-common/src/libmooncake_common.so /opt/mooncake/lib/

ldconfig


  # -DCMAKE_BUILD_TYPE=Release \
cmake \
  -DPYBIND11_FINDPYTHON=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="/opt/mooncake" \
  -DBUILD_UNIT_TESTS=ON \
  -DBUILD_EXAMPLES=ON \
  -DUSE_HTTP=ON \
  -DUSE_REDIS=ON \
  -DUSE_CUDA=OFF \
  -DUSE_ETCD=ON \
  -DWITH_STORE=ON \
  -DSTORE_USE_ETCD=ON \
  -S. -Bbuild -GNinja && \
  cmake --build build --target all && \
  LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/mooncake/lib:/usr/local/lib::$PWD/build/mooncake-common/etcd \
  bash ./scripts/build_wheel.sh 3.12 dist


# uninstall old te
pip list|grep mooncake
pip uninstall -y mooncake-transfer-engine

# install
cd mooncake-wheel/dist
mc_pkg=$(ls)
echo $mc_pkg
pip install $mc_pkg
cd -
# pip install mooncake_transfer_engine-0.3.5-cp312-cp312-manylinux_2_17_x86_64.manylinux_2_35_x86_64.whl
# pip install mooncake-wheel/dist/*.whl

