package com.leisurexi.elk.log.scheduler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * @author: leisurexi
 * @date: 2020-04-22 23:42
 * @since JDK 1.8
 */
@EnableScheduling
@Configuration
public class LogScheduler {

    private static Logger log = LoggerFactory.getLogger(LogScheduler.class);

    @Scheduled(cron = " 0/30 * * * * ? ")
    public void doTiming() {
        log.info("ELK测试日志");
    }

}
