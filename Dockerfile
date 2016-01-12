FROM thrively/zulu8-maven
MAINTAINER thrively

RUN mkdir /build

COPY ./ build/

WORKDIR /build

RUN /opt/apache-maven-3.3.3/bin/mvn install -DskipTests=true
EXPOSE 8443

ENV KEY_STORE=**changeme**
ENV KEY_STORE_PASSWORD=**changeme**
ENV KEY_ID=**changeme**
ENV GITHUB_ORG=**changeme**
ENV GITHUB_USERS=**changeme**
ENV AUDIENCE=**changeme**
ENV ISSUER=**changeme**

CMD /usr/bin/java $JAVA_OPTS $JAVA_SSL_OPTS -XX:OnOutOfMemoryError="kill -9 %p" -jar target/authserver-1.0.one-jar.jar
