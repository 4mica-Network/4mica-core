pub use async_trait::async_trait;
use log::error;
use std::sync::Arc;
use tokio_cron_scheduler::{Job, JobScheduler};

#[async_trait]
pub trait Task: Send + Sync + 'static {
    fn cron_pattern(&self) -> String;

    async fn run(&self) -> anyhow::Result<()>;
}

pub struct TaskScheduler {
    scheduler: JobScheduler,
}

impl Drop for TaskScheduler {
    fn drop(&mut self) {
        let mut scheduler = self.scheduler.clone();
        tokio::spawn(async move {
            if let Err(e) = scheduler.shutdown().await {
                error!("Failed to shutdown task scheduler: {e}");
            }
        });
    }
}

impl TaskScheduler {
    pub async fn new() -> anyhow::Result<Self> {
        let scheduler = JobScheduler::new().await?;
        Ok(Self { scheduler })
    }

    pub async fn add_task(&mut self, task: Arc<dyn Task>) -> anyhow::Result<()> {
        let job = Job::new_async(task.cron_pattern(), move |_id, _lock| {
            let task = task.clone();
            Box::pin(async move {
                if let Err(e) = task.run().await {
                    error!("Failed to run task: {e}");
                }
            })
        })?;
        self.scheduler.add(job).await?;

        Ok(())
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        self.scheduler.start().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::{Duration, sleep};

    struct CounterTask {
        counter: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Task for CounterTask {
        fn cron_pattern(&self) -> String {
            // Run every second
            "* * * * * *".to_string()
        }

        async fn run(&self) -> anyhow::Result<()> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_scheduler_increments_counter() {
        let counter = Arc::new(AtomicUsize::new(0));
        let task = Arc::new(CounterTask {
            counter: counter.clone(),
        });

        let mut scheduler = TaskScheduler::new().await.unwrap();
        scheduler.add_task(task).await.unwrap();
        scheduler.start().await.unwrap();

        // Wait for 3 seconds
        sleep(Duration::from_secs(3)).await;

        // Counter should have incremented at least 2 times
        // (allowing some margin for scheduler startup)
        let count = counter.load(Ordering::SeqCst);
        assert!(
            count >= 2,
            "Expected counter to be at least 2, but got {}",
            count
        );
    }
}
