### [MSA] Eureka Client, Gateway | Daily products information project

## SKill
<img src="https://img.shields.io/badge/JAVA-007396?style=flat-square&logo=java&logoColor=white"> <img src="https://img.shields.io/badge/Spring Boot-6DB33F?style=flat-square&logo=SpringBoot&logoColor=white"> <img src="https://img.shields.io/badge/Spring Security-6DB33F?style=flat-square&logo=Spring Security&logoColor=white"> <img src="https://img.shields.io/badge/Spring Batch-6DB33F?style=flat-square&logo=Spring&logoColor=white"> <img src="https://img.shields.io/badge/JPA-007396?style=flat-square&logo=java&logoColor=white"> <img src="https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=Docker&logoColor=white"> <img src="https://img.shields.io/badge/Github-181717?style=flat-square&logo=github&logoColor=white"> 

<img src="https://img.shields.io/badge/Service Discovery-E50914?style=flat-square&logo=java&logoColor=white"> <img src="https://img.shields.io/badge/Linux-FCC624?style=flat-square&logo=linux&logoColor=black"> <img src="https://img.shields.io/badge/Apache Tomcat-F8DC75?style=flat-square&logo=apachetomcat&logoColor=white">


## Database
<img src="https://img.shields.io/badge/MySQL-4479A1?style=flat-square&logo=MySQL&logoColor=white"> <img src="https://img.shields.io/badge/Redis-DC382D?style=flat-square&logo=Redis&logoColor=white">

## Features and Configurations
- Rest API
- JWT (User)
- SMTP (User)
- Batch (Product)
- Gateway (Filter, Load balancing)
- WebFlux non-blocking system (Product)
- GitHub Config Server (Properties)
- Docker Container (Redis)
- Docker Container (MySQL Master/Slave)

## Microservices Architecture
![BE  전체구조](https://user-images.githubusercontent.com/13326651/213702803-65d7a5fd-4ec3-4c7c-b4cd-cbf66a8f21af.png)

## Server Side Discovery
서비스를 사용할 클라이언트와 Service Registry 사이에 Load Balancer(현 프로젝트에서는 SC Gateway가 역할 수행)를 두고 Service Registry에 호출할 서비스의 위치를 질의하는 방식

## Srping MVC
동기적으로 동작하는 블로킹으로 사용자 요청이 들어올때마다 스레드를 생성해서 처리한다. 요청당 스레드를 생성하기 때문에 이를 방지 하기 위해서 스레드풀을 만들어서 사용한다
이 동작의 단점은 스레드풀을 초과하는 요청이 왔을때는 큐에 요청이 쌓여 지연되는 상황이 발생한다. 이 문제를 아래 WebFlux에서 해결한다.

## WebFlux + Netty
Spring Framwork5에서 새롭게 추가된 모듈, 적은 양의 스레드와 최소한의 하드웨어 자원으로 동시성을 핸들링하기 위해 만들어졌다. 
서블릿 3.1이 논블로킹을 지원하지만, 일부분으로 이는 새로운 공통 API가 생긴 이유가 됐으며, netty와 같이 잘 만들어진 async, non-blocking 서버를 사용한다.

JPA 기본적으로 비동기를 제공하지 않는다. 즉, Webflux 기반에서 JPA를 사용하면 Database 부분에서 block되고, 그 동안 thread가 기다리게 된다. 즉 의미가 없다는 얘기다.
이러한 문제를 해결하기 위해 나온 것이 R2DBC(Reactive Relational DataBase Connectivity) 관계형 데이터베이스 driver specification에 대한 non-blocking alternative를 제공 한다.
따라서 JpaRepository 대신 ReactiveCrudRepository를 사용한다.

## Spring MVC vs Spring WebFlux
![mvc,webflux](https://user-images.githubusercontent.com/13326651/213714186-b4c7de56-8dd7-4f0c-96da-fc3d3be4fca1.png)

## Distribution
java -jar -DSpring.profiles.active=[profiles-dev] [build.jar]

## option (no hang up &)
nohup java -jar -DSpring.profiles.active=[profile-env] [build.jar] &

## Reference
- https://docs.spring.io/spring-framework/docs/current/reference/html/web-reactive.html
- https://heeyeah.github.io/spring/2020-02-29-web-flux/
- https://binux.tistory.com/154
