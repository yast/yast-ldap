FROM yastdevel/cpp:sle15-sp1
RUN zypper --gpg-auto-import-keys --non-interactive in --no-recommends \
  libldapcpp-devel \
  yast2-perl-bindings
COPY . /usr/src/app

