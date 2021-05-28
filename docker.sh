 release_version=$@

 docker build --build-arg GOPROXY=https://goproxy.cn --build-arg VERSION=${release_version} --build-arg KUBECTLDOWNLOADURL=http://download.jumpserver.org/public/kubectl.tar.gz -t 2970298425/koko:$release_version .

 docker push 2970298425/koko:$release_version