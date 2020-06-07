FROM java:8-jdk-alpine
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
COPY ./target/log-0.0.1-SNAPSHOT.jar /usr/app/
WORKDIR /usr/app
RUN sh -c 'touch log-0.0.1-SNAPSHOT.jar'
ENTRYPOINT ["java", "-jar", "log-0.0.1-SNAPSHOT.jar"]