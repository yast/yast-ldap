FROM registry.opensuse.org/yast/sle-15/sp2/containers/yast-cpp
RUN zypper --gpg-auto-import-keys --non-interactive in --no-recommends \
  libldapcpp-devel \
  yast2-perl-bindings
COPY . /usr/src/app

