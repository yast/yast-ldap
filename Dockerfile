FROM registry.opensuse.org/yast/head/containers/yast-cpp:latest
RUN zypper --gpg-auto-import-keys --non-interactive in --no-recommends \
  libldapcpp-devel \
  yast2-perl-bindings
COPY . /usr/src/app

