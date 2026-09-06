use std::sync::Arc;
use std::sync::atomic::{AtomicBool,Ordering};
use std::thread::{self,JoinHandle};
use std::time::Duration;
use crate::prometheus::MetricsRegistry;

pub const DB_STATS_INTERVAL:Duration=Duration::from_secs(6*60*60);
pub trait DbStat:Send+Sync+'static{fn stats(&self)->Result<Vec<String>,String>;fn engine(&self)->&str;fn name(&self)->&str;}
#[derive(Clone,Debug,PartialEq)]pub struct DbLevelStat{pub level:String,pub files:f64,pub size_bytes:f64}
pub fn parse_db_stat(line:&str)->Result<DbLevelStat,String>{let fields:Vec<_>=line.split_whitespace().collect();if fields.len()<3{return Err(format!("invalid DB stat row: {line}"))}let files=fields[1].parse::<f64>().map_err(|e|e.to_string())?;let mib=fields[2].parse::<f64>().map_err(|e|e.to_string())?;Ok(DbLevelStat{level:fields[0].to_owned(),files,size_bytes:mib*1_048_576.0})}
pub fn collect_db_stats(db:&dyn DbStat,metrics:&MetricsRegistry)->Result<Vec<DbLevelStat>,String>{let rows=db.stats()?;let mut parsed=Vec::with_capacity(rows.len());for row in rows{let stat=parse_db_stat(&row)?;let _=metrics.gauge_set("tron:db_sst_level",stat.files,&[db.engine(),db.name(),&stat.level]);let _=metrics.gauge_set("tron:db_size_bytes",stat.size_bytes,&[db.engine(),db.name(),&stat.level]);parsed.push(stat)}Ok(parsed)}

pub struct DbStatService{enabled:bool,interval:Duration,metrics:MetricsRegistry,stop:Arc<AtomicBool>,threads:Vec<JoinHandle<()>>}
impl DbStatService{#[must_use]pub fn new(metrics:MetricsRegistry)->Self{let enabled=metrics.enabled();Self{enabled,interval:DB_STATS_INTERVAL,metrics,stop:Arc::new(AtomicBool::new(false)),threads:Vec::new()}}#[must_use]pub fn with_interval(metrics:MetricsRegistry,interval:Duration)->Self{let mut service=Self::new(metrics);service.interval=interval;service}pub fn register(&mut self,db:Arc<dyn DbStat>){if !self.enabled{return}let stop=Arc::clone(&self.stop);let metrics=self.metrics.clone();let interval=self.interval;self.threads.push(thread::spawn(move||{while !stop.load(Ordering::Acquire){let _=collect_db_stats(db.as_ref(),&metrics);let deadline=std::time::Instant::now()+interval;while !stop.load(Ordering::Acquire)&&std::time::Instant::now()<deadline{thread::sleep(Duration::from_millis(100).min(interval));}}}))}pub fn shutdown(&mut self){self.stop.store(true,Ordering::Release);for handle in self.threads.drain(..){let _=handle.join();}}}
impl Drop for DbStatService{fn drop(&mut self){self.shutdown()}}
