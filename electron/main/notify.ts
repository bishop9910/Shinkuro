import { Notification } from 'electron';
import { NotifyOption } from '../../type';

export function showNotification(options: NotifyOption): void{
  let notify = new Notification({
    title: options.title,
    body: options.body
  });
  notify.show();
}