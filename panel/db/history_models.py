"""The History rollups: one game server's or one host's samples over one hour, kept a year.

Kept apart from models.py (which imports them back, so `from panel.db.models import MetricHourly` works)
only for size. Built and pruned by panel/services/history_rollup.py.
"""
from panel.db.sqla import db


class MetricHourly(db.Model):
    """One game server's MetricSamples over one hour: the History ranges from 30 days to a year read these.

    Built by panel/services/history_rollup.py from the samples (average, highest and lowest CPU% and RAM
    MB, the most players seen) and kept a year, so a year is ~8,760 rows per server where the samples
    would be ~525,000. Cleared with its server, like MetricSample.
    """

    __tablename__ = "metric_hourly"
    # One row per server per hour: the rollup replaces an hour it builds again, never adds to it.
    # The year's prune deletes on `hour < cutoff` alone, hence the single-column index too.
    __table_args__ = (db.Index("ux_metric_hourly_server_hour", "server_id", "hour", unique=True),)
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, nullable=False)
    hour = db.Column(db.DateTime, nullable=False, index=True)   # the hour's start, UTC
    n = db.Column(db.Integer, nullable=False, default=0)        # samples in the hour
    cpu_avg = db.Column(db.Float)
    cpu_max = db.Column(db.Float)
    cpu_min = db.Column(db.Float)
    ram_avg = db.Column(db.Float)
    ram_max = db.Column(db.Float)
    ram_min = db.Column(db.Float)
    players_max = db.Column(db.Integer, nullable=True)          # None = no sample knew the count


class HostHourly(db.Model):
    """One host's HostSamples over one hour, for the host History ranges from 30 days to a year.

    Average, highest and lowest CPU%, RAM% and disk%, and the average and highest network rates.
    Built and kept like MetricHourly; cleared with its host.
    """

    __tablename__ = "host_hourly"
    __table_args__ = (db.Index("ux_host_hourly_remote_hour", "remote_id", "hour", unique=True),)
    id = db.Column(db.Integer, primary_key=True)
    remote_id = db.Column(db.Integer, nullable=False)
    hour = db.Column(db.DateTime, nullable=False, index=True)
    n = db.Column(db.Integer, nullable=False, default=0)
    cpu_avg = db.Column(db.Float)
    cpu_max = db.Column(db.Float)
    cpu_min = db.Column(db.Float)
    ram_avg = db.Column(db.Float)
    ram_max = db.Column(db.Float)
    ram_min = db.Column(db.Float)
    disk_avg = db.Column(db.Float)
    disk_max = db.Column(db.Float)
    disk_min = db.Column(db.Float)
    rx_avg = db.Column(db.Float, nullable=True)
    rx_max = db.Column(db.Float, nullable=True)
    tx_avg = db.Column(db.Float, nullable=True)
    tx_max = db.Column(db.Float, nullable=True)
