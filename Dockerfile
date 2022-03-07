FROM adoptopenjdk/openjdk11:jdk-11.0.2.7-alpine-slim
#ADD java.security /opt/java/openjdk/conf/security
COPY target/zuul-service-0.0.1-SNAPSHOT.jar .
EXPOSE 9090
CMD java -jar zuul-service-0.0.1-SNAPSHOT.jar
