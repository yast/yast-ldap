FROM yastdevel/cpp-tw
RUN zypper --gpg-auto-import-keys --non-interactive in --no-recommends \
  libldapcpp-devel
COPY . /tmp/sources

