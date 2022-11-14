# Java
About Java Security and Development

关于 EL 表达式RCE如何回显的跟踪调试

测试环境：JDK8U201、Tomcat9.0.0.M26

所需 maven 依赖

    <dependency>
        <groupId>javax.servlet</groupId>
        <artifactId>javax.servlet-api</artifactId>
        <version>3.1.0</version>
    </dependency>
    <dependency>
        <groupId>javax.servlet.jsp</groupId>
        <artifactId>jsp-api</artifactId>
        <version>2.2</version>
    </dependency>
    <dependency>
        <groupId>org.apache.tomcat</groupId>
        <artifactId>tomcat-el-api</artifactId>
        <version>9.0.0.M26</version>
    </dependency>

所用 jar 包不限于以上所列
