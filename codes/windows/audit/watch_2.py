import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class OnMyWatch:
    # Set the directory on watch
    watch_dir = r"C:\Users\Cu Lee\Desktop\Test"

    def __init__(self):
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.watch_dir, recursive=True)
        self.observer.start()

        try:
            while True:
                time.sleep(5)
        except Exception as e:
            print(e)
            self.observer.stop()
            print("Observer Stopped")
        self.observer.join()


class Handler(FileSystemEventHandler):
    @staticmethod
    def on_any_event(event_log):
        if event_log.is_directory:
            return None
        elif event_log.event_type == 'created':
            print("Watchdog received created event - % s." % event_log.src_path)
        elif event_log.event_type == 'modified':
            # Event is modified, you can process it now
            print("Watchdog received modified event - % s." % event_log.src_path)


def monitor():
    watch = OnMyWatch()
    watch.run()
