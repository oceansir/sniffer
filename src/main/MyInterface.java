package main;

import java.awt.*;
import java.awt.event.*;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;

public class MyInterface extends JFrame{
	
	JMenuBar menubar;   //�˵���
	JMenu menuFile1,menuFile2; //�˵�
	JMenuItem[] item;   //�˵���
	JMenuItem pro1,pro2,pro3;
	JTextField searchText;
	JButton sipButton,dipButton;
//	searchButton;
	JPanel panel;  
	JScrollPane scrollPane;  
	JTable table;  
	final String[] head = new String[] {
		"time","source ip", "dest ip", "protocol", "packet length"
	};
	NetworkInterface[] devices;
	Object[][] datalist = {};
	// packet view list
	DefaultTableModel tableModel;
	// packet list
	PacketCapture allpackets;
	
	public MyInterface(){
		allpackets = new PacketCapture();
		this.setTitle("Sniffer");
		this.setBounds(650, 150, 1200, 1000);
		menubar = new JMenuBar();
		build();   
	}

	public void build() {
		networkMenu(); 
		protocolMenu();
		
		sourceIpButton();
		destIpButton();
		
//		searchButton(); 
		
		setJMenuBar(menubar);
		
		packetListTable();  
		detailInforJframe();
		

		setResizable(false);
		setVisible(true);
		addWindowListener(new WindowAdapter() {  
			public void windowClosing(WindowEvent e) {  
				System.exit(0);
			}  

		});
	}

	public void detailInforJframe() {
		table.addMouseListener(new MouseAdapter(){
			public void mouseClicked(MouseEvent ev){
				if(ev.getClickCount() == 2){
					int row = table.getSelectedRow();
					
					// ��ϸ��Ϣ
					JFrame frame = new JFrame("detail info");
					JPanel panel = new JPanel();
					final JTextArea info = new JTextArea(23, 42);
					info.setEditable(false);
					info.setLineWrap(true);
					info.setWrapStyleWord(true);
					frame.add(panel);
					panel.add(new JScrollPane(info));
//					JButton save = new JButton("���浽����");
//					save.addActionListener(  
//						new ActionListener(){  
//							public void actionPerformed(ActionEvent e3) {  
//								String text = info.getText();
//								int name = (int)System.currentTimeMillis();
//								try {  
//									FileOutputStream fos = new FileOutputStream("d://"+name+".txt");   
//									fos.write(text.getBytes());  
//									fos.close();  
//								} catch (Exception e) {   
//									e.printStackTrace();  
//								} 
//							}  
//						}); 
//					panel.add(save);
					frame.setBounds(150, 150, 500, 500);
					frame.setVisible(true);
					frame.setResizable(false);
					ArrayList<Packet> packetlist = allpackets.getpacketlist();
					Map<String,String> hm1 = new HashMap<String,String>();
					Map<String,String> hm2 = new HashMap<String,String>();
					Packet packet = packetlist.get(row);
					
					info.append("IPͷ��Ϣ��\n");
					hm1 = new PacketAnalyze(packet).IPanalyze();
					for(Map.Entry<String,String> me1 : hm1.entrySet()){
						info.append(me1.getKey()+" : "+me1.getValue()+"\n");
						System.out.println(me1.getValue());
					}
					hm2 = new PacketAnalyze(packet).packetClass();
					info.append("\n" + hm2.get("Э��")+"\n");
					for(Map.Entry<String,String> me : hm2.entrySet()) {
						info.append(me.getKey()+" : "+me.getValue()+"\n");
					}
				}
			}
		});
	}
	

	public void packetListTable() {
		// packet view list
		tableModel = new DefaultTableModel(datalist, head);
		table = new JTable(tableModel){
			public boolean isCellEditable(int row, int column){
				return false;
			}
		};
		allpackets.setTable(tableModel);	
		table.setPreferredScrollableViewportSize(new Dimension(500, 60));// ���ñ��Ĵ�С 
		table.setRowHeight(30);// ����ÿ�еĸ߶�Ϊ20
		table.setRowMargin(5);// �����������е�Ԫ��ľ���  
		table.setRowSelectionAllowed(true);// ���ÿɷ�ѡ��.Ĭ��Ϊfalse  
		table.setSelectionBackground(Color.cyan);// ������ѡ���еı���ɫ  
		table.setSelectionForeground(Color.red);// ������ѡ���е�ǰ��ɫ  
		table.setShowGrid(true);// �Ƿ���ʾ������   
		table.doLayout();   
		scrollPane = new JScrollPane(table); 
		panel = new JPanel(new GridLayout(0, 1));  
		panel.setPreferredSize(new Dimension(600, 300));  
		panel.setBackground(Color.black);  
		panel.add(scrollPane); 
		
		
		
		setContentPane(panel);  
		
		
		pack();
	}

//	public void searchButton() {
//		//���ݹؼ��ֽ��й���
//		searchButton = new JButton(" search  ");
//		searchButton.addActionListener(  
//			new ActionListener(){  
//				public void actionPerformed(ActionEvent e) {  
//					String fkeyword = JOptionPane.showInputDialog("Please enter the data keyword to filter packets:");    
//					allpackets.setFilter("keyword "+fkeyword);
//					allpackets.clearpackets();
//					while(tableModel.getRowCount()>0){
//						tableModel.removeRow(tableModel.getRowCount()-1);
//					}
//				}  
//			});
//		//���˵���ӵ��˵�����
//		menubar.add(searchButton);
//	}

	public void destIpButton() {
		//����Ŀ��IP���й���
		dipButton = new JButton(" dest ip ");
		dipButton.addActionListener(  
			new ActionListener(){  
				public void actionPerformed(ActionEvent e) {  
					String fdip = JOptionPane.showInputDialog("Please enter the destination IP address to filter packets:");  
					allpackets.setFilter("dip "+fdip);
					allpackets.clearpackets();
					while(tableModel.getRowCount()>0){
						tableModel.removeRow(tableModel.getRowCount()-1);
					}
				}  
			});
		menubar.add(dipButton);
	}

	public void sourceIpButton() {
		//����ԴIP���й���
		sipButton = new JButton(" source ip ");
		sipButton.addActionListener(  
			new ActionListener(){  
				public void actionPerformed(ActionEvent e) {  
					String fsip = JOptionPane.showInputDialog("Please enter the source IP address to filter packets:");  
					allpackets.setFilter("sip "+fsip);
					allpackets.clearpackets();
					while(tableModel.getRowCount()>0){
						tableModel.removeRow(tableModel.getRowCount()-1);
					}
				}  
			});
		menubar.add(sipButton);
	}

	public void protocolMenu() {
		//����Э����й���
		menuFile2 = new JMenu("  protocol  ");
		pro1 = new JMenuItem("ICMP");
		pro2 = new JMenuItem("TCP");
		pro3 = new JMenuItem("UDP");
		pro1.addActionListener(  
			new ActionListener(){  
				public void actionPerformed(ActionEvent e3) {  
					allpackets.setFilter("ICMP");
					allpackets.clearpackets();
					while(tableModel.getRowCount()>0){
						tableModel.removeRow(tableModel.getRowCount()-1);
					}
				}  
			}); 
		pro2.addActionListener(  
			new ActionListener(){  
				public void actionPerformed(ActionEvent e3) {  
					allpackets.setFilter("TCP");
					allpackets.clearpackets();
					while(tableModel.getRowCount()>0){
						tableModel.removeRow(tableModel.getRowCount()-1);
					}
				}  
			});
		pro3.addActionListener(  
			new ActionListener(){  
				public void actionPerformed(ActionEvent e3) {  
					allpackets.setFilter("UDP");
					allpackets.clearpackets();
					while(tableModel.getRowCount()>0){
						tableModel.removeRow(tableModel.getRowCount()-1);
					}
				}  
			}); 
		menuFile2.add(pro1);
		menuFile2.add(pro2);
		menuFile2.add(pro3);
		
		menubar.add(menuFile2);
	}

	public void networkMenu() {
		//�����������й���
		menuFile1 = new JMenu(" network card ");
		NetworkInterface[] devices = new NetworkCard().getDevices();
		item = new JMenuItem[devices.length];
		for (int i = 0; i < devices.length; i++) {
			item[i] = new JMenuItem(i + ": " + devices[i].name + "("
					+ devices[i].description  + ")");
			menuFile1.add(item[i]);
			item[i].addActionListener(new CardActionListener(devices[i]));
		}
		menubar.add(menuFile1);
	}

	private class CardActionListener implements ActionListener{

		NetworkInterface device;
		CardActionListener(NetworkInterface device){
			this.device = device;
		}
		public void actionPerformed(ActionEvent e) {
			allpackets.setDevice(device);
			allpackets.setFilter("");
			new Thread(allpackets).start();   //����ץ���߳�
		}     
	}  
}